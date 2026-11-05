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

// Exercises the real hook path, both embedded scorers, redaction and SQLite.
// Commands are data passed to EvaluateHook; none is executed.
func TestAWSOperationsShadowHookToSQLite(t *testing.T) {
	s, store := newClassifierServer(t)
	defer s.Close()
	baseline, err := riskclassifier.LoadSVM()
	if err != nil {
		t.Fatal(err)
	}
	commands := []string{
		`aws secretsmanager get-secret-value --secret-id fixture-secret --query SecretString --output text`,
		strings.Repeat("# ordinary setup context\n", 500) + `VALUE=$(aws secretsmanager get-secret-value --secret-id fixture-secret --query SecretString --output text)`,
		`aws secretsmanager describe-secret --secret-id fixture-secret`,
		`printf '%s\n' 'aws secretsmanager get-secret-value --secret-id example'`,
		`aws secretsmanager get-secret-value --secret-id fixture-secret --generate-cli-skeleton`,
	}
	for i, command := range commands {
		result, err := s.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
			SessionID: "sess_operations", Agent: "claude", HookName: hook.HookPreToolUse,
			ToolName: "Bash", ToolInput: map[string]any{"command": command},
		})
		if err != nil {
			t.Fatal(err)
		}
		if result.Decision != hook.DecisionAllow {
			t.Fatalf("shadow changed authorization: %s", result.Decision)
		}
		records := verdictsFor(t, store, "sess_operations", i+1)
		var found bool
		for _, record := range records {
			if record.ActionID != result.EventID {
				continue
			}
			found = true
			want := baseline.Classify(command)
			if record.SVM == nil || *record.SVM != want {
				t.Fatalf("legacy score changed: %+v, want %+v", record.SVM, want)
			}
			if record.Operations == nil || !record.Operations.Shadow {
				t.Fatal("missing durable shadow annotation")
			}
			if i < 2 && (record.Operations.Verdict != riskclassifier.VerdictRisky || record.Operations.CombinedVerdict != riskclassifier.VerdictRisky) {
				t.Fatalf("secret read missed: %+v", record.Operations)
			}
			if i == 1 && !record.CommandTruncated {
				t.Fatal("fixture must exceed stored evidence cap")
			}
			if i >= 2 && record.Operations.Verdict == riskclassifier.VerdictRisky {
				t.Fatalf("routine/nonexecuted operation flagged: %+v", record.Operations)
			}
			if record.Enforced {
				t.Fatal("shadow must not enforce")
			}
		}
		if !found {
			t.Fatal("hook annotation was not persisted")
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
	if strings.Contains(string(wire), "aws-operations/") {
		t.Fatal("local shadow model leaked into signed/uploaded facts")
	}
}

func TestAWSOperationsRemainLocalAndSkipNonShell(t *testing.T) {
	s, _ := newClassifierServer(t)
	defer s.Close()
	for _, tool := range []string{"Bash", "apply_patch"} {
		verdict := s.classifier.Classify(context.Background(), "sess_local", tool,
			`aws secretsmanager get-secret-value --secret-id never-store-this-argument`)
		if tool == "Bash" && verdict.Operations == nil {
			t.Fatal("missing shell operation score")
		}
		if tool != "Bash" && verdict.Operations != nil {
			t.Fatal("non-shell tool scored as an AWS invocation")
		}
		if verdict.Operations != nil {
			body, err := json.Marshal(verdict.Operations)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(body), "never-store-this-argument") {
				t.Fatal("operation annotation leaked argument values")
			}
		}
	}
}
