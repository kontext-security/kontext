// Package antigravity registers the Antigravity agent adapter. The Antigravity
// app, CLI and IDE share one hook format with its own event names and payloads;
// see hookruntime.DecodeAntigravityEvent for the mapping.
package antigravity

import (
	"github.com/kontext-security/kontext/internal/agent"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/hookruntime"
)

func init() {
	agent.Register(&Antigravity{})
}

// Antigravity decodes one event, named by the hook command: its payloads do not
// say which event they belong to.
type Antigravity struct {
	event hook.HookName
}

func (a *Antigravity) Name() string { return "antigravity" }

// ForEvent is the adapter for the event a hook command names.
func (a *Antigravity) ForEvent(event hook.HookName) agent.Agent {
	return &Antigravity{event: event}
}

func (a *Antigravity) DecodeHookInput(input []byte) (hook.Event, error) {
	return hookruntime.DecodeAntigravityEvent(input, a.Name(), a.event)
}

// NoDecision keeps the person's approval prompt. A failing hook, or "{}" from
// PreToolUse, would block the call instead.
func (a *Antigravity) NoDecision() []byte { return hookruntime.AntigravityNoDecision() }

func (a *Antigravity) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return hookruntime.EncodeAntigravityResult(event.HookName, result)
}
