package agenthooks

import (
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

func TestPlanValidation(t *testing.T) {
	plan := testPlan(map[string]string{"PreToolUse": "owned"})
	plan.Version = "future"
	if err := plan.Validate(); err == nil {
		t.Fatal("Validate() error = nil, want bad version error")
	}
}

func testPlan(commands map[string]string) Plan {
	events := make(map[hook.HookName]EventPlan, len(commands))
	for name, command := range commands {
		events[hook.HookName(name)] = EventPlan{
			Match: MatchSpec{Pattern: ""},
			Command: CommandHook{
				Command: command,
			},
			Placement: PlacementAppend,
		}
	}
	return Plan{
		Version:  SchemaVersionV1,
		Provider: ProviderClaudeCode,
		Owner:    OwnerKontextManagedObserve,
		Events:   events,
	}
}
