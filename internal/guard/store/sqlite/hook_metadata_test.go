package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kontext-security/kontext/internal/guard/risk"
)

func TestSaveDecisionPreservesHookMetadata(t *testing.T) {
	duration, zero, large := int64(4187), int64(0), int64(9007199254740993)
	interrupted, notInterrupted := true, false
	for _, test := range []struct {
		name  string
		event risk.HookEvent
		want  map[string]any
	}{
		{"failure", risk.HookEvent{HookEventName: "PostToolUseFailure", DurationMs: &duration, Error: "failed: Bearer fake-hook-secret", IsInterrupt: &interrupted, PermissionMode: "default"}, map[string]any{"duration_ms": duration, "error_redacted": "failed: Bearer [REDACTED_SECRET]", "is_interrupt": true, "permission_mode": "default"}},
		{"zero and false", risk.HookEvent{HookEventName: "PostToolUse", DurationMs: &zero, IsInterrupt: &notInterrupted}, map[string]any{"duration_ms": zero, "is_interrupt": false}},
		{"absent", risk.HookEvent{HookEventName: "PostToolUseFailure"}, nil},
		{"pre-tool permission", risk.HookEvent{HookEventName: "PreToolUse", PermissionMode: "acceptEdits"}, map[string]any{"permission_mode": "acceptEdits"}},
		{"unsafe integer omitted", risk.HookEvent{HookEventName: "PreToolUse", DurationMs: &large}, nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			store, err := OpenStore(t.TempDir() + "/guard.db")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			test.event.SessionID, test.event.ToolUseID, test.event.ToolName = "session", "tool", "Bash"
			_, err = store.SaveDecision(ctx, test.event, risk.RiskDecision{Decision: risk.DecisionAllow, Reason: "policy reason must not become a tool error"})
			if err != nil {
				t.Fatal(err)
			}
			var wantJSON string
			if test.want != nil {
				raw, err := json.Marshal(test.want)
				if err != nil {
					t.Fatal(err)
				}
				wantJSON = string(raw)
			}
			rows, err := store.db.QueryContext(ctx, `select a.context_json, a.context_hash, a.error_redacted, r.receipt_payload_json from authorization_actions a join authorization_receipts r on r.action_id = a.id`)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for rows.Next() {
				var contextJSON, contextHash, errorRedacted, receiptJSON string
				if err := rows.Scan(&contextJSON, &contextHash, &errorRedacted, &receiptJSON); err != nil {
					t.Fatal(err)
				}
				if got := string(hookMetadataFromContext(contextJSON)); got != wantJSON {
					t.Fatalf("metadata = %s, want %s", got, wantJSON)
				}
				if contextHash != hashString(contextJSON) {
					t.Fatal("context hash does not bind metadata")
				}
				var receipt struct {
					Action struct {
						HookMetadata json.RawMessage `json:"hook_metadata"`
					} `json:"action"`
					Outcome map[string]any `json:"outcome"`
				}
				if err := json.Unmarshal([]byte(receiptJSON), &receipt); err != nil {
					t.Fatal(err)
				}
				if got := string(receipt.Action.HookMetadata); got != wantJSON {
					t.Fatalf("signed metadata = %s, want %s", got, wantJSON)
				}
				wantError, _ := test.want["error_redacted"].(string)
				if errorRedacted != wantError {
					t.Fatalf("error_redacted = %q, want %q", errorRedacted, wantError)
				}
				if receipt.Outcome != nil && receipt.Outcome["error_redacted"] != wantError {
					t.Fatalf("receipt error = %v, want %q", receipt.Outcome["error_redacted"], wantError)
				}
				if strings.Contains(contextJSON+receiptJSON, "fake-hook-secret") {
					t.Fatal("unredacted secret persisted")
				}
				count++
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			rows.Close()
			wantCount := 1
			if test.event.HookEventName == "PreToolUse" {
				wantCount = 2
			}
			if count != wantCount {
				t.Fatalf("rows = %d, want %d", count, wantCount)
			}
			if err := store.VerifyReceipts(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHookDurationExportIntegrity(t *testing.T) {
	t.Setenv(ledgerSigningEnv, "1")
	const maxSafeDuration = int64(1<<53 - 1)
	for _, hookName := range []string{"PostToolUse", "PostToolUseFailure"} {
		for _, duration := range []int64{0, 4187, maxSafeDuration, maxSafeDuration + 1, maxSafeDuration + 2, 1<<63 - 1, -1} {
			t.Run(fmt.Sprintf("%s/%d", hookName, duration), func(t *testing.T) {
				ctx := context.Background()
				store, err := OpenStore(t.TempDir() + "/guard.db")
				if err != nil {
					t.Fatal(err)
				}
				defer store.Close()
				notInterrupted := false
				_, err = store.SaveDecision(ctx, risk.HookEvent{
					SessionID: "session", ToolUseID: "tool", ToolName: "Bash",
					HookEventName: hookName, DurationMs: &duration, IsInterrupt: &notInterrupted,
				}, risk.RiskDecision{Decision: risk.DecisionAllow})
				if err != nil {
					t.Fatal(err)
				}
				batch, err := store.LedgerBatch(ctx, LedgerExportOptions{})
				if err != nil {
					t.Fatal(err)
				}
				wire, err := json.Marshal(batch)
				if err != nil {
					t.Fatal(err)
				}
				// Exercise the actual wire payload through a float64 JSON consumer,
				// as used by the exporter and the hosted JavaScript API.
				var exported LedgerBatch
				if err := json.Unmarshal(wire, &exported); err != nil {
					t.Fatal(err)
				}
				if len(exported.Actions) != 1 || len(exported.Receipts) != 1 {
					t.Fatalf("export counts = %d actions, %d receipts", len(exported.Actions), len(exported.Receipts))
				}
				contextPayload := exported.Actions[0]["context_json"].(map[string]any)
				metadata := contextPayload["hook_metadata"].(map[string]any)
				got, present := metadata["duration_ms"]
				wantPresent := duration >= 0 && duration <= maxSafeDuration
				if present != wantPresent || (present && got != float64(duration)) {
					t.Fatalf("exported duration = %v (present %t), input = %d", got, present, duration)
				}
				if metadata["is_interrupt"] != false {
					t.Fatal("invalid duration must not remove other provider metadata")
				}
				receipt := exported.Receipts[0]
				payload, err := json.Marshal(receipt["receipt_payload_json"])
				if err != nil {
					t.Fatal(err)
				}
				receiptHash := hashString(string(payload))
				if receiptHash != receipt["receipt_hash"] {
					t.Fatal("exported receipt no longer matches its signed hash")
				}
				if err := store.verifyReceiptSignature(receiptHash, stringValue(receipt["signature"]), stringValue(receipt["signature_algorithm"]), stringValue(receipt["key_id"])); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestHookMetadataSurvivesReceiptReconstructionAndReopen(t *testing.T) {
	t.Setenv("KONTEXT_GUARD_LEDGER_SIGNING", "1")
	ctx := context.Background()
	path := t.TempDir() + "/guard.db"
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	// A record without metadata has the historical payload shape.
	old, err := store.SaveDecision(ctx, risk.HookEvent{SessionID: "s", HookEventName: "PostToolUse"}, risk.RiskDecision{})
	if err != nil {
		t.Fatal(err)
	}
	var oldPayload string
	if err := store.db.QueryRowContext(ctx, `select receipt_payload_json from authorization_receipts where action_id = ?`, old.ID).Scan(&oldPayload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(oldPayload, "hook_metadata") {
		t.Fatal("missing metadata should not change the historical payload shape")
	}
	duration := int64(17)
	newRecord, err := store.SaveDecision(ctx, risk.HookEvent{SessionID: "s", HookEventName: "PostToolUse", DurationMs: &duration, PermissionMode: "default"}, risk.RiskDecision{})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var reopenedPayload string
	if err := store.db.QueryRowContext(ctx, `select receipt_payload_json from authorization_receipts where action_id = ?`, old.ID).Scan(&reopenedPayload); err != nil {
		t.Fatal(err)
	}
	if reopenedPayload != oldPayload {
		t.Fatal("historical signed receipt was rewritten")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	action, err := receiptActionValues(ctx, tx, newRecord.ID)
	if err != nil {
		t.Fatal(err)
	}
	input := receiptInputFromAction(action, "outcome", newRecord.CreatedAt)
	metadata := input.Payload["action"].(map[string]any)["hook_metadata"]
	if string(metadata.(json.RawMessage)) != `{"duration_ms":17,"permission_mode":"default"}` {
		t.Fatalf("reconstructed metadata = %s", metadata)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyReceipts(ctx); err != nil {
		t.Fatal(err)
	}
	// New metadata is covered by the receipt's signature/hash, not merely
	// appended to an unsigned sidecar. Historical receipts still verify above.
	if _, err := store.db.ExecContext(ctx, `update authorization_receipts set receipt_payload_json = replace(receipt_payload_json, '"duration_ms":17', '"duration_ms":18') where action_id = ?`, newRecord.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyReceipts(ctx); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("VerifyReceipts after metadata tampering = %v, want hash mismatch", err)
	}
}

func TestRedactHookTextBoundsAndSecrets(t *testing.T) {
	for _, test := range []struct {
		name, value string
		limit       int
	}{
		{"secret crosses truncation boundary", strings.Repeat("x", 4050) + " Bearer secret-prefix-must-not-survive-" + strings.Repeat("z", 100), 4096},
		{"unicode", strings.Repeat("界", 2000), 4096},
		{"oversized", strings.Repeat("x", (1<<20)+1), 4096},
		{"permission mode", "Bearer secret-prefix-must-not-survive-" + strings.Repeat("z", 300), 256},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := redactHookText(test.value, test.limit)
			if len(got) > test.limit || !utf8.ValidString(got) {
				t.Fatalf("invalid bounded output: %d bytes", len(got))
			}
			if strings.Contains(got, "secret-prefix") {
				t.Fatal("secret prefix survived redaction")
			}
			if test.name == "oversized" && !strings.Contains(got, "omitted") {
				t.Fatal("oversized input must be omitted before redaction")
			}
		})
	}
}
