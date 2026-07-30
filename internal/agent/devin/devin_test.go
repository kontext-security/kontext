package devin

import (
	"errors"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestDevinRegisteredUnderItsName(t *testing.T) {
	t.Parallel()

	registered, ok := agent.Get("devin")
	if !ok {
		t.Fatal("agent.Get(\"devin\") not found, want the adapter registered")
	}
	if registered.Name() != "devin" {
		t.Fatalf("Name() = %q, want devin", registered.Name())
	}
}

func TestDecodeHookInputStampsAgentName(t *testing.T) {
	t.Parallel()

	event, err := (&Devin{}).DecodeHookInput([]byte(
		`{"hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"command":"ls"}}`,
	))
	if err != nil {
		t.Fatalf("DecodeHookInput() error = %v", err)
	}
	if event.Agent != "devin" {
		t.Fatalf("Agent = %q, want devin", event.Agent)
	}
}

func TestDecodeHookInputReportsSkipForEventsWithoutDecisions(t *testing.T) {
	t.Parallel()

	_, err := (&Devin{}).DecodeHookInput([]byte(`{"hook_event_name":"PostCompaction"}`))
	if !errors.Is(err, hook.ErrSkipEvent) {
		t.Fatalf("DecodeHookInput() error = %v, want ErrSkipEvent", err)
	}
}

func TestEncodeHookResultUsesTheEventOnTheEvent(t *testing.T) {
	t.Parallel()

	out, err := (&Devin{}).EncodeHookResult(
		hook.Event{HookName: hook.HookPreToolUse},
		hook.Result{Decision: hook.DecisionDeny, Reason: "denied by policy"},
	)
	if err != nil {
		t.Fatalf("EncodeHookResult() error = %v", err)
	}
	if want := `{"decision":"block","reason":"denied by policy"}`; string(out) != want {
		t.Fatalf("EncodeHookResult() = %s, want %s", out, want)
	}
}
