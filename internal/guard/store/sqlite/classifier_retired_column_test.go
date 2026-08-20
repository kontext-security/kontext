package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/risk"
)

// A database written by an earlier build of this branch still has the retired
// classifier_json column. Opening it must not rebuild, fail, or lose the chain.
func TestUpgradeFromBranchDatabaseWithRetiredColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.db")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID: "sess_old", HookEventName: "PreToolUse", ToolName: "Bash",
		ToolInput: map[string]any{"command": "ls"},
	}, risk.RiskDecision{Decision: risk.DecisionAllow, ReasonCode: "normal_tool_call"}); err != nil {
		t.Fatalf("seed decision: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("raw open: %v", err)
	}
	if _, err := raw.Exec(`alter table authorization_actions add column classifier_json text`); err != nil {
		t.Fatalf("simulate old column: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("raw close: %v", err)
	}

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen with retired column present: %v", err)
	}
	defer reopened.Close()
	if _, err := reopened.SaveDecision(context.Background(), risk.HookEvent{
		SessionID: "sess_old", HookEventName: "PreToolUse", ToolName: "Bash",
		ToolInput: map[string]any{"command": "rm -rf /tmp/x"},
	}, risk.RiskDecision{
		Decision: risk.DecisionAllow, ReasonCode: "normal_tool_call",
		Classifier: &risk.ClassifierAnnotation{
			SVM: &risk.ClassifierSVM{Verdict: "risky", Score: 1.2, Threshold: 0.4, ModelVersion: "0.1.0"},
		},
	}); err != nil {
		t.Fatalf("save after upgrade: %v", err)
	}
	if err := reopened.VerifyReceipts(context.Background()); err != nil {
		t.Fatalf("receipt chain broke across the upgrade: %v", err)
	}
	actions, err := reopened.AuthorizationActions(context.Background(), LedgerExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	for _, action := range actions {
		if _, present := action["classifier_json"]; present {
			t.Error("retired column leaked into the export")
		}
	}
}
