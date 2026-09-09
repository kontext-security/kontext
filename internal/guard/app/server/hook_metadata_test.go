package server

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/hookruntime"
	"github.com/kontext-security/kontext/internal/localruntime"
)

func TestRiskHookEventPreservesProviderMetadata(t *testing.T) {
	duration, zero := int64(4187), int64(0)
	interrupted, notInterrupted := true, false
	for name, event := range map[string]hook.Event{
		"present":        {DurationMs: &duration, Error: "command failed", IsInterrupt: &interrupted, PermissionMode: "default"},
		"zero and false": {DurationMs: &zero, IsInterrupt: &notInterrupted},
		"absent":         {},
	} {
		t.Run(name, func(t *testing.T) {
			event.SessionID = "session"
			event.HookName = hook.HookPostToolUseFailed
			converted := riskEventFromHookEvent(event)
			if got := hookEventFromRiskEvent(converted); !reflect.DeepEqual(got, event) {
				t.Fatalf("round trip = %#v, want %#v", got, event)
			}
			// The legacy Guard HTTP edge also accepts these optional fields.
			wire, err := json.Marshal(converted)
			if err != nil {
				t.Fatal(err)
			}
			var decoded risk.HookEvent
			if err := json.Unmarshal(wire, &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, converted) {
				t.Fatalf("JSON round trip = %#v, want %#v", decoded, converted)
			}
		})
	}
}

func TestProviderMetadataReachesLedgerThroughHookTransport(t *testing.T) {
	for _, test := range []struct {
		name, input string
		decode      func([]byte, string) (hook.Event, error)
		want        map[string]any
	}{
		{
			name:   "claude failure without tool response",
			input:  `{"session_id":"sess_e2e","hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_use_id":"tool-1","tool_input":{"command":"npm test"},"duration_ms":4187,"error":"failed: Bearer secret-for-hook-test","is_interrupt":false,"permission_mode":"default"}`,
			decode: hookruntime.DecodeClaudeEvent,
			want:   map[string]any{"duration_ms": float64(4187), "error_redacted": "failed: Bearer [REDACTED_SECRET]", "is_interrupt": false, "permission_mode": "default"},
		},
		{
			name:   "codex permission mode with unavailable execution fields",
			input:  `{"session_id":"sess_e2e","hook_event_name":"PostToolUse","tool_name":"Bash","tool_use_id":"tool-1","tool_input":{"command":"npm test"},"tool_response":{"exit_code":0},"permission_mode":"default"}`,
			decode: hookruntime.DecodeCodexEvent,
			want:   map[string]any{"permission_mode": "default"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			event, err := test.decode([]byte(test.input), "test-agent")
			if err != nil {
				t.Fatal(err)
			}
			req, err := localruntime.EvaluateRequestFromEvent(event)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			var received localruntime.EvaluateRequest
			if err := json.Unmarshal(wire, &received); err != nil {
				t.Fatal(err)
			}
			event, err = localruntime.EventFromEvaluateRequest("", "", &received)
			if err != nil {
				t.Fatal(err)
			}
			server, store := newClassifierServer(t)
			result, err := server.RuntimeCore().ProcessHook(context.Background(), event)
			if err != nil {
				t.Fatal(err)
			}
			batch, err := store.LedgerBatch(context.Background(), sqlite.LedgerExportOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if len(batch.Actions) != 1 || batch.Actions[0]["id"] != result.EventID {
				t.Fatalf("actions = %#v", batch.Actions)
			}
			contextPayload := batch.Actions[0]["context_json"].(map[string]any)
			if got := contextPayload["hook_metadata"]; !reflect.DeepEqual(got, test.want) {
				t.Fatalf("stored metadata = %#v, want %#v", got, test.want)
			}
			if len(batch.Receipts) != 1 {
				t.Fatalf("receipts = %d, want 1", len(batch.Receipts))
			}
			payload := batch.Receipts[0]["receipt_payload_json"].(map[string]any)
			if got := payload["action"].(map[string]any)["hook_metadata"]; !reflect.DeepEqual(got, test.want) {
				t.Fatalf("signed metadata = %#v, want %#v", got, test.want)
			}
			exported, err := json.Marshal(batch)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(exported), "secret-for-hook-test") {
				t.Fatal("raw error secret leaked into ledger export")
			}
			if err := store.VerifyReceipts(context.Background()); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeferredRecordingPreservesProviderPermissionMode(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var jobs []func(context.Context) error
	server, err := NewServerWithPolicyAndOptions(store, nil, Options{
		DeferRecord: func(job func(context.Context) error) { jobs = append(jobs, job) },
	})
	if err != nil {
		t.Fatal(err)
	}
	// The legacy HTTP ingress goes through the reverse conversion first.
	result, err := server.ProcessHookEvent(ctx, risk.HookEvent{
		SessionID: "session", HookEventName: "PreToolUse", ToolName: "Read",
		ToolInput: map[string]any{"file_path": "/tmp/example"}, PermissionMode: "acceptEdits",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("deferred jobs = %d, want 1", len(jobs))
	}
	actions, err := store.AuthorizationActions(ctx, sqlite.LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 0 {
		t.Fatal("hook response waited for metadata persistence")
	}
	if err := jobs[0](ctx); err != nil {
		t.Fatal(err)
	}
	actions, err = store.AuthorizationActions(ctx, sqlite.LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 {
		t.Fatalf("actions = %d, want proposed and decided", len(actions))
	}
	found := false
	for _, action := range actions {
		metadata := action["context_json"].(map[string]any)["hook_metadata"].(map[string]any)
		if metadata["permission_mode"] != "acceptEdits" {
			t.Fatalf("deferred metadata = %#v", metadata)
		}
		found = found || action["id"] == result.EventID
	}
	if !found {
		t.Fatal("deferred decision lost its preassigned action ID")
	}
}
