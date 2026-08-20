package hookruntime

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/agent/claude"
	"github.com/kontext-security/kontext/internal/hook"
)

func TestAgentAdapterDecodePreservesHookEvent(t *testing.T) {
	t.Parallel()

	input := strings.NewReader(`{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":".env"},"tool_use_id":"toolu_123","cwd":"/tmp/project"}`)
	event, err := AgentAdapter{Agent: &claude.Claude{}, AgentName: "claude-code"}.Decode(input)
	if err != nil {
		t.Fatal(err)
	}
	if event.HookName != hook.HookPreToolUse || !event.HookName.CanBlock() {
		t.Fatalf("event = %+v, want blocking PreToolUse", event)
	}
	if event.Agent != "claude-code" ||
		event.SessionID != "s1" ||
		event.ToolName != "Read" ||
		event.ToolUseID != "toolu_123" ||
		event.CWD != "/tmp/project" {
		t.Fatalf("event = %+v, want decoded metadata", event)
	}
	if event.ToolInput["file_path"] != ".env" {
		t.Fatalf("tool input = %+v", event.ToolInput)
	}
}

func TestAgentAdapterEncodeObserveModeAllowsWouldDeny(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := AgentAdapter{Agent: &claude.Claude{}, AgentName: "claude-code"}.Encode(
		&out,
		hook.Event{HookName: hook.HookPreToolUse},
		hook.Result{Decision: hook.DecisionAllow, Reason: "Kontext observe mode: would deny; blocked", Mode: string(ModeObserve)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"allow"`) {
		t.Fatalf("output = %s", out.String())
	}
	if !strings.Contains(out.String(), `would deny; blocked`) {
		t.Fatalf("output = %s", out.String())
	}
}

func TestAgentAdapterEncodeEnforceModeDenies(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	err := AgentAdapter{Agent: &claude.Claude{}, AgentName: "claude-code"}.Encode(
		&out,
		hook.Event{HookName: hook.HookPreToolUse},
		hook.Result{Decision: hook.DecisionDeny, Reason: "blocked", Mode: string(ModeEnforce)},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("output = %s", out.String())
	}
}
