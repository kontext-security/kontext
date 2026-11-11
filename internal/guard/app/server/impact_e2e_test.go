package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hook"
)

// Real hook -> native models -> SQLite -> signed fact/export. Never executes input.
func TestKestrelImpactAdvisoryHookToSignedFact(t *testing.T) {
	s, store := newClassifierServer(t)
	defer s.Close()
	commands := []string{`pkill -f "apps/web/server.js"`, `printf ready`, strings.Repeat("x", 65537)}
	for i, command := range commands {
		result, err := s.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
			SessionID: "impact_e2e", Agent: "claude", HookName: hook.HookPreToolUse,
			ToolUseID: []string{"impact-flag", "impact-quiet", "impact-limit"}[i], ToolName: "Bash", ToolInput: map[string]any{"command": command},
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Decision != hook.DecisionAllow {
			t.Fatalf("advisory model changed decision: %+v", result)
		}
		records := verdictsFor(t, store, "impact_e2e", i+1)
		var found bool
		for _, record := range records {
			if record.ActionID == result.EventID {
				found = true
				if record.Impact == nil || record.Enforced || record.Impact.Enforced {
					t.Fatalf("missing or enforced impact: %+v", record)
				}
				if record.Impact.Threshold != riskclassifier.ImpactThreshold {
					t.Fatalf("wrong pilot setting: %+v", record.Impact)
				}
				if i == 0 && record.Impact.Verdict != "flagged" {
					t.Fatalf("missed flag: %+v", record.Impact)
				}
				if i == 1 && record.Impact.Verdict != "below_threshold" {
					t.Fatalf("routine command flagged: %+v", record.Impact)
				}
				if i == 2 && (record.Impact.Verdict != "not_assessed" || record.Impact.Score != nil) {
					t.Fatalf("limit silently assessed: %+v", record.Impact)
				}
			}
		}
		if !found {
			t.Fatal("missing persisted annotation")
		}
	}
	actions, err := store.AuthorizationActions(context.Background(), sqlite.LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(actions)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(wire), `"impact"`) || !strings.Contains(string(wire), riskclassifier.ImpactModelSHA256) {
		t.Fatal("Impact lost before upload")
	}
}

func TestKestrelImpactPilotCanBeDisabled(t *testing.T) {
	t.Setenv("KONTEXT_KESTREL_IMPACT_ENABLED", "false")
	s, _ := newClassifierServer(t)
	defer s.Close()
	v := s.classifier.Classify(context.Background(), "session", "Bash", "pkill -x unbound")
	if v.Impact != nil || v.SVM == nil {
		t.Fatalf("Impact kill switch affects existing Kestrel: %+v", v)
	}
}
