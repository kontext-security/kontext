package sqlite

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
)

func TestRiskTypeEnrichmentIsAppendOnlyIdempotentAndShellOnly(t *testing.T) {
	store := openClassifierTestStore(t)
	ctx := context.Background()
	model, err := riskclassifier.LoadRiskTypeSVM()
	if err != nil {
		t.Fatal(err)
	}

	shell := saveRiskyClassifierCall(t, store, "sess_risk_types", "tool_shell", "Bash", "launchctl load ~/Library/LaunchAgents/com.example.agent.plist")
	saveRiskyClassifierCall(t, store, "sess_risk_types", "tool_patch", "apply_patch", "*** Begin Patch\n*** Update File: x\n*** End Patch")

	var factBefore, receiptBefore string
	if err := store.db.QueryRowContext(ctx, `select decision_fact_json from authorization_actions where id = ?`, shell.ID).Scan(&factBefore); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `select receipt_payload_json from authorization_receipts where action_id = ? order by created_at desc limit 1`, shell.ID).Scan(&receiptBefore); err != nil {
		t.Fatal(err)
	}

	first, err := store.EnrichRiskyShellCalls(ctx, model)
	if err != nil {
		t.Fatalf("first enrichment: %v", err)
	}
	if first.EligibleRisky != 1 || first.Inserted != 1 || first.IneligibleRisky != 1 || len(first.Items) != 1 {
		t.Fatalf("first enrichment = %+v", first)
	}
	if first.Items[0].ActionID != shell.ID {
		t.Fatalf("enriched action = %s, want %s", first.Items[0].ActionID, shell.ID)
	}

	second, err := store.EnrichRiskyShellCalls(ctx, model)
	if err != nil {
		t.Fatalf("second enrichment: %v", err)
	}
	if second.Inserted != 0 || second.AlreadyPresent != 1 || !second.Items[0].AlreadyPresent {
		t.Fatalf("second enrichment was not idempotent: %+v", second)
	}

	annotations, cursor, err := store.RiskTypeAnnotations(ctx, RiskTypeAnnotationExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(annotations) != 1 || cursor == nil {
		t.Fatalf("annotations/cursor = %d/%+v, want one", len(annotations), cursor)
	}
	if annotations[0].InputKind != riskclassifier.RiskTypeInputStoredRedactedCommand {
		t.Fatalf("input kind = %q", annotations[0].InputKind)
	}

	var factAfter, receiptAfter string
	if err := store.db.QueryRowContext(ctx, `select decision_fact_json from authorization_actions where id = ?`, shell.ID).Scan(&factAfter); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRowContext(ctx, `select receipt_payload_json from authorization_receipts where action_id = ? order by created_at desc limit 1`, shell.ID).Scan(&receiptAfter); err != nil {
		t.Fatal(err)
	}
	if factAfter != factBefore || receiptAfter != receiptBefore {
		t.Fatal("retrospective enrichment rewrote signed historical evidence")
	}
}

func TestRiskTypeAnnotationRequiresMatchingActionIdentity(t *testing.T) {
	store := openClassifierTestStore(t)
	model, err := riskclassifier.LoadRiskTypeSVM()
	if err != nil {
		t.Fatal(err)
	}
	verdict := model.Classify("launchctl load ~/Library/LaunchAgents/com.example.agent.plist")
	record := riskclassifier.RiskTypeRecord{
		ActionID:    "act_00000000-0000-0000-0000-000000000000",
		SessionID:   "session",
		ToolUseID:   "tool",
		CommandHash: "hash",
		InputKind:   riskclassifier.RiskTypeInputRawCommand,
		Verdict:     verdict,
	}
	if _, _, err := store.SaveRiskTypeAnnotation(context.Background(), record); err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("unknown-action error = %v", err)
	}

	action := saveRiskyClassifierCall(t, store, "session", "tool", "Bash", "launchctl load ~/Library/LaunchAgents/com.example.agent.plist")
	record.ActionID = action.ID
	record.SessionID = "wrong-session"
	if _, _, err := store.SaveRiskTypeAnnotation(context.Background(), record); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("session-mismatch error = %v", err)
	}
	record.SessionID = "session"
	record.ToolUseID = "wrong-tool"
	if _, _, err := store.SaveRiskTypeAnnotation(context.Background(), record); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("tool-mismatch error = %v", err)
	}
}

func TestRiskTypeAnnotationExportWaitsForActionCursor(t *testing.T) {
	store := openClassifierTestStore(t)
	action := saveRiskyClassifierCall(t, store, "session", "tool", "Bash", "launchctl load ~/Library/LaunchAgents/com.example.agent.plist")
	model, err := riskclassifier.LoadRiskTypeSVM()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.SaveRiskTypeAnnotation(context.Background(), riskclassifier.RiskTypeRecord{
		ActionID:    action.ID,
		SessionID:   "session",
		ToolUseID:   "tool",
		CommandHash: "hash-tool",
		InputKind:   riskclassifier.RiskTypeInputRawCommand,
		Verdict:     model.Classify("launchctl load ~/Library/LaunchAgents/com.example.agent.plist"),
	}); err != nil {
		t.Fatal(err)
	}

	before := time.Unix(0, 0).UTC()
	annotations, _, err := store.RiskTypeAnnotations(context.Background(), RiskTypeAnnotationExportOptions{ActionUpdatedThrough: &before})
	if err != nil {
		t.Fatal(err)
	}
	if len(annotations) != 0 {
		t.Fatalf("annotations before action cursor = %d, want 0", len(annotations))
	}
	batch, err := store.LedgerBatch(context.Background(), LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Cursor == nil {
		t.Fatal("action cursor is nil")
	}
	annotations, _, err = store.RiskTypeAnnotations(context.Background(), RiskTypeAnnotationExportOptions{
		ActionUpdatedThrough:   &batch.Cursor.UpdatedAt,
		ActionUpdatedThroughID: batch.Cursor.ActionID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(annotations) != 1 || annotations[0].ActionID != action.ID {
		t.Fatalf("annotations through action cursor = %+v", annotations)
	}
}

func saveRiskyClassifierCall(t *testing.T, store *Store, sessionID, toolUseID, toolName, command string) DecisionRecord {
	t.Helper()
	ctx := context.Background()
	decision, err := store.SaveDecision(ctx, risk.HookEvent{
		SessionID:     sessionID,
		Agent:         "codex",
		HookEventName: "PreToolUse",
		ToolName:      toolName,
		ToolUseID:     toolUseID,
		ToolInput:     map[string]any{"command": command},
	}, risk.RiskDecision{Decision: risk.DecisionAllow, Reason: "allowed", ReasonCode: "test"})
	if err != nil {
		t.Fatalf("save %s decision: %v", toolName, err)
	}
	if _, err := store.SaveClassifierVerdict(ctx, riskclassifier.Record{
		ActionID:    decision.ID,
		SessionID:   sessionID,
		ToolUseID:   toolUseID,
		Agent:       "codex",
		Command:     command,
		CommandHash: "hash-" + toolUseID,
		SVM: &riskclassifier.SVMVerdict{
			Verdict:      riskclassifier.VerdictRisky,
			Score:        0.5,
			Threshold:    0.4,
			ModelVersion: "binary-test/1",
		},
	}); err != nil {
		t.Fatalf("save %s classifier row: %v", toolName, err)
	}
	return decision
}
