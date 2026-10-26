// Package cursor registers the Cursor agent adapter. Cursor (the IDE agent and
// the cursor-agent CLI) runs command hooks from hooks.json with its own event
// names and payloads; see hookruntime.DecodeCursorEvent for the mapping.
package cursor

import (
	"github.com/kontext-security/kontext/internal/agent"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/hookruntime"
)

func init() {
	agent.Register(&Cursor{})
}

type Cursor struct{}

func (c *Cursor) Name() string { return "cursor" }

func (c *Cursor) DecodeHookInput(input []byte) (hook.Event, error) {
	return hookruntime.DecodeCursorEvent(input, c.Name())
}

// NoDecision is Cursor's "no decision" answer. Skipped events (an MCP call's
// preToolUse copy, events Kontext does not handle) must still print it: a
// fail-closed hook that prints nothing blocks the call.
func (c *Cursor) NoDecision() []byte { return []byte("{}") }

func (c *Cursor) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return hookruntime.EncodeCursorResult(event.HookName, result)
}
