package codex

import (
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/agent"
	"github.com/kontext-security/kontext/internal/hook"
)

func TestCodexRegistersAgent(t *testing.T) {
	t.Parallel()

	a, ok := agent.Get("codex")
	if !ok {
		t.Fatal("codex agent was not registered")
	}
	if a.Name() != "codex" {
		t.Fatalf("Name() = %q, want codex", a.Name())
	}
}

func TestCodexAdapterDecodesAndEncodes(t *testing.T) {
	t.Parallel()

	c := &Codex{}
	event, err := c.DecodeHookInput([]byte(`{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"pwd"}}`))
	if err != nil {
		t.Fatalf("DecodeHookInput() error = %v", err)
	}
	if event.SessionID != "codex-s1" || event.Agent != "codex" || event.HookName != hook.HookPreToolUse {
		t.Fatalf("event = %+v, want codex PreToolUse", event)
	}

	out, err := c.EncodeHookResult(event, hook.Result{Decision: hook.DecisionAllow, Reason: "allowed"})
	if err != nil {
		t.Fatalf("EncodeHookResult() error = %v", err)
	}
	if strings.Contains(string(out), "suppressOutput") {
		t.Fatalf("EncodeHookResult() = %s, want no suppressOutput", out)
	}
}
