package primeagent

import (
	"encoding/json"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestRegistryResolvesPrimeAgentAndAlias(t *testing.T) {
	for _, name := range []string{"prime-agent", "primeagent"} {
		if _, ok := agent.Get(name); !ok {
			t.Fatalf("agent %q was not registered", name)
		}
	}
}

func TestDecodeHookInputUsesClaudeFormatWithPrimeAgentName(t *testing.T) {
	input := []byte(`{
		"session_id": "prime-session-1",
		"hook_event_name": "PreToolUse",
		"tool_name": "bash",
		"tool_input": {"command": "rm -rf /"},
		"tool_use_id": "call-1",
		"cwd": "/tmp/project"
	}`)

	event, err := (&PrimeAgent{}).DecodeHookInput(input)
	if err != nil {
		t.Fatalf("DecodeHookInput: %v", err)
	}
	if event.Agent != "prime-agent" {
		t.Fatalf("event agent = %q, want %q", event.Agent, "prime-agent")
	}
	if event.HookName != hook.HookPreToolUse {
		t.Fatalf("event hook = %q, want %q", event.HookName, hook.HookPreToolUse)
	}
	if event.SessionID != "prime-session-1" {
		t.Fatalf("session id = %q, want %q", event.SessionID, "prime-session-1")
	}
	if event.ToolName != "bash" {
		t.Fatalf("tool name = %q, want %q", event.ToolName, "bash")
	}
	if event.ToolUseID != "call-1" {
		t.Fatalf("tool use id = %q, want %q", event.ToolUseID, "call-1")
	}
	if got := event.ToolInput["command"]; got != "rm -rf /" {
		t.Fatalf("tool input command = %v, want %q", got, "rm -rf /")
	}
}

func TestEncodeHookResultEmitsClaudePermissionDecision(t *testing.T) {
	event := hook.Event{HookName: hook.HookPreToolUse}
	result := hook.Result{Decision: hook.DecisionDeny, Reason: "blocked by policy"}

	out, err := (&PrimeAgent{}).EncodeHookResult(event, result)
	if err != nil {
		t.Fatalf("EncodeHookResult: %v", err)
	}

	var decoded struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if decoded.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Fatalf("hook event name = %q, want PreToolUse", decoded.HookSpecificOutput.HookEventName)
	}
	if decoded.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("permission decision = %q, want deny", decoded.HookSpecificOutput.PermissionDecision)
	}
	if decoded.HookSpecificOutput.PermissionDecisionReason != "blocked by policy" {
		t.Fatalf("reason = %q, want %q", decoded.HookSpecificOutput.PermissionDecisionReason, "blocked by policy")
	}
}
