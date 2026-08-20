// Package codex registers the Codex agent adapter.
package codex

import (
	"github.com/kontext-security/kontext/internal/agent"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/hookruntime"
)

func init() {
	agent.Register(&Codex{})
}

type Codex struct{}

func (c *Codex) Name() string { return "codex" }

func (c *Codex) DecodeHookInput(input []byte) (hook.Event, error) {
	return hookruntime.DecodeCodexEvent(input, c.Name())
}

func (c *Codex) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return hookruntime.EncodeCodexResult(event.HookName.String(), result)
}
