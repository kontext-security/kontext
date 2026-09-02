package hookruntime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

func TestDecodeCodexEventPreToolUse(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"abc123",
		"hook_event_name":"PreToolUse",
		"tool_name":"Bash",
		"tool_use_id":"call_123",
		"tool_input":{"command":"npm test","id":9007199254740993},
		"cwd":"/tmp/project",
		"permission_mode":"default"
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.SessionID != "codex-abc123" {
		t.Fatalf("SessionID = %q, want prefixed id", event.SessionID)
	}
	if event.Agent != "codex" ||
		event.HookName != hook.HookPreToolUse ||
		event.ToolName != "Bash" ||
		event.ToolUseID != "call_123" ||
		event.CWD != "/tmp/project" ||
		event.PermissionMode != "default" {
		t.Fatalf("event = %+v, want decoded metadata", event)
	}
	if event.ToolInput["command"] != "npm test" {
		t.Fatalf("ToolInput[command] = %v, want npm test", event.ToolInput["command"])
	}
	if num, ok := event.ToolInput["id"].(json.Number); !ok || num.String() != "9007199254740993" {
		t.Fatalf("ToolInput[id] = %v (%T), want json.Number", event.ToolInput["id"], event.ToolInput["id"])
	}
}

func TestDecodeCodexEventPreservesExistingSessionPrefix(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{"session_id":"codex-abc123","hook_event_name":"SessionStart","source":"startup"}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.SessionID != "codex-abc123" {
		t.Fatalf("SessionID = %q, want unchanged prefixed id", event.SessionID)
	}
}

func TestDecodeCodexEventSessionStartPreservesSource(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"s1",
		"hook_event_name":"SessionStart",
		"source":"resume",
		"tool_input":{"reason":"startup"}
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.HookName != hook.HookSessionStart {
		t.Fatalf("HookName = %q, want SessionStart", event.HookName)
	}
	if event.ToolInput["source"] != "resume" {
		t.Fatalf("ToolInput[source] = %v, want resume", event.ToolInput["source"])
	}
	if event.ToolInput["reason"] != "startup" {
		t.Fatalf("ToolInput[reason] = %v, want startup", event.ToolInput["reason"])
	}
}

func TestDecodeCodexEventUserPromptSubmitPreservesPrompt(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"s1",
		"hook_event_name":"UserPromptSubmit",
		"prompt":"ship it",
		"tool_input":{"model":"gpt-5-codex"}
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.HookName != hook.HookUserPromptSubmit {
		t.Fatalf("HookName = %q, want UserPromptSubmit", event.HookName)
	}
	if event.ToolInput["prompt"] != "ship it" {
		t.Fatalf("ToolInput[prompt] = %v, want prompt", event.ToolInput["prompt"])
	}
	if event.ToolInput["model"] != "gpt-5-codex" {
		t.Fatalf("ToolInput[model] = %v, want gpt-5-codex", event.ToolInput["model"])
	}
}

func TestDecodeCodexEventTopLevelPromptTakesPrecedence(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"s1",
		"hook_event_name":"UserPromptSubmit",
		"prompt":"top-level prompt",
		"tool_input":{"prompt":"nested prompt"}
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.ToolInput["prompt"] != "top-level prompt" {
		t.Fatalf("ToolInput[prompt] = %v, want top-level prompt", event.ToolInput["prompt"])
	}
}

func TestDecodeCodexEventStop(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"s1",
		"hook_event_name":"Stop",
		"last_assistant_message":"done"
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	if event.HookName != hook.HookStop {
		t.Fatalf("HookName = %q, want Stop", event.HookName)
	}
}

func TestDecodeCodexEventRejectsClaudeOnlyLifecycleHooks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "post tool use failure",
			input: `{"session_id":"s1","hook_event_name":"PostToolUseFailure","tool_name":"Bash"}`,
		},
		{
			name:  "session end",
			input: `{"session_id":"s1","hook_event_name":"SessionEnd","tool_input":{"reason":"exit"}}`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := DecodeCodexEvent([]byte(tt.input), "codex")
			if err == nil {
				t.Fatal("DecodeCodexEvent() error = nil, want unsupported event error")
			}
			if !strings.Contains(err.Error(), "unsupported hook event") {
				t.Fatalf("DecodeCodexEvent() error = %v, want unsupported hook event", err)
			}
		})
	}
}

func TestDecodeCodexEventPostToolUsePreservesArrayResponse(t *testing.T) {
	t.Parallel()

	event, err := DecodeCodexEvent([]byte(`{
		"session_id":"s1",
		"hook_event_name":"PostToolUse",
		"tool_name":"mcp__fs__read",
		"tool_response":[{"id":9007199254740993}]
	}`), "codex")
	if err != nil {
		t.Fatalf("DecodeCodexEvent() error = %v", err)
	}
	content, ok := event.ToolResponse["content"].([]any)
	if !ok || len(content) != 1 {
		t.Fatalf("ToolResponse[content] = %v (%T), want one item", event.ToolResponse["content"], event.ToolResponse["content"])
	}
	id := content[0].(map[string]any)["id"]
	if num, ok := id.(json.Number); !ok || num.String() != "9007199254740993" {
		t.Fatalf("response id = %v (%T), want json.Number", id, id)
	}
}

func TestDecodeCodexEventRejectsUnsupportedPermissionRequest(t *testing.T) {
	t.Parallel()

	_, err := DecodeCodexEvent([]byte(`{"hook_event_name":"PermissionRequest"}`), "codex")
	if err == nil {
		t.Fatal("DecodeCodexEvent() error = nil, want unsupported event error")
	}
	if !strings.Contains(err.Error(), "unsupported hook event") {
		t.Fatalf("DecodeCodexEvent() error = %v, want unsupported hook event", err)
	}
}

func TestEncodeCodexPreToolUseDenyOmitsSuppressOutput(t *testing.T) {
	t.Parallel()

	out, err := EncodeCodexResult("PreToolUse", hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Blocked by policy",
	})
	if err != nil {
		t.Fatalf("EncodeCodexResult() error = %v", err)
	}
	text := string(out)
	if !strings.Contains(text, `"permissionDecision":"deny"`) || !strings.Contains(text, "Blocked by policy") {
		t.Fatalf("EncodeCodexResult() = %s, want deny decision and reason", text)
	}
	if strings.Contains(text, "suppressOutput") {
		t.Fatalf("EncodeCodexResult() = %s, want no suppressOutput", text)
	}
}

func TestEncodeCodexPreToolUseAllowUpdatedInputOmitsSuppressOutput(t *testing.T) {
	t.Parallel()

	out, err := EncodeCodexResult("PreToolUse", hook.Result{
		Decision:     hook.DecisionAllow,
		Reason:       "allowed",
		UpdatedInput: map[string]any{"command": "echo rewritten"},
	})
	if err != nil {
		t.Fatalf("EncodeCodexResult() error = %v", err)
	}
	text := string(out)
	if !strings.Contains(text, `"permissionDecision":"allow"`) || !strings.Contains(text, `"updatedInput"`) {
		t.Fatalf("EncodeCodexResult() = %s, want allow decision and updatedInput", text)
	}
	if strings.Contains(text, "suppressOutput") {
		t.Fatalf("EncodeCodexResult() = %s, want no suppressOutput", text)
	}
}

func TestEncodeCodexAllowNoOpOmitsSuppressOutput(t *testing.T) {
	t.Parallel()

	out, err := EncodeCodexResult("PostToolUse", hook.Result{
		Decision: hook.DecisionAllow,
		Reason:   "async telemetry event recorded",
	})
	if err != nil {
		t.Fatalf("EncodeCodexResult() error = %v", err)
	}
	if got := string(out); got != "{}" {
		t.Fatalf("EncodeCodexResult() = %s, want empty object", got)
	}
	if strings.Contains(string(out), "suppressOutput") {
		t.Fatalf("EncodeCodexResult() = %s, want no suppressOutput", out)
	}
}

func TestEncodeCodexUserPromptSubmitDenyBlocks(t *testing.T) {
	t.Parallel()

	out, err := EncodeCodexResult("UserPromptSubmit", hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Ask for confirmation first",
	})
	if err != nil {
		t.Fatalf("EncodeCodexResult() error = %v", err)
	}
	text := string(out)
	if !strings.Contains(text, `"decision":"block"`) || !strings.Contains(text, "Ask for confirmation first") {
		t.Fatalf("EncodeCodexResult() = %s, want block decision", text)
	}
	if strings.Contains(text, "suppressOutput") {
		t.Fatalf("EncodeCodexResult() = %s, want no suppressOutput", text)
	}
}

func TestEncodeCodexStopNoOps(t *testing.T) {
	t.Parallel()

	out, err := EncodeCodexResult("Stop", hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "Run another pass",
	})
	if err != nil {
		t.Fatalf("EncodeCodexResult() error = %v", err)
	}
	if got := string(out); got != "{}" {
		t.Fatalf("EncodeCodexResult() = %s, want empty object", got)
	}
}

func TestEncodeCodexRejectsUnsupportedEvent(t *testing.T) {
	t.Parallel()

	_, err := EncodeCodexResult("PermissionRequest", hook.Result{Decision: hook.DecisionAllow})
	if err == nil {
		t.Fatal("EncodeCodexResult() error = nil, want unsupported event error")
	}
}

func TestDecodeCodexEventMissingToolInputIsEmptyObject(t *testing.T) {
	t.Parallel()

	for _, toolInput := range []string{`"tool_input":null,`, ``} {
		event, err := DecodeCodexEvent([]byte(`{"session_id":"abc","hook_event_name":"PreToolUse","tool_name":"shell",`+toolInput+`"cwd":"/tmp"}`), "codex")
		if err != nil {
			t.Fatalf("DecodeCodexEvent() error = %v", err)
		}
		if event.ToolInput == nil || len(event.ToolInput) != 0 {
			t.Fatalf("ToolInput = %#v, want empty object for %q", event.ToolInput, toolInput)
		}
	}
}
