// Package cowork registers the Cowork agent adapter. Claude Cowork runs the
// same bundled Claude Code CLI inside a per-session VM, so its hook payloads
// arrive in the standard hook wire format. The adapter therefore reuses the
// standard codec and only differs in its name, which is recorded as the
// session's agent ("cowork") to distinguish Cowork activity from Claude Code
// in the ledger and dashboard.
package cowork

import (
	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
)

func init() {
	agent.Register(&Cowork{})
}

type Cowork struct{}

func (c *Cowork) Name() string { return "cowork" }

func (c *Cowork) Aliases() []string { return []string{"claude-cowork"} }

func (c *Cowork) DecodeHookInput(input []byte) (hook.Event, error) {
	return hookruntime.DecodeStandardEvent(input, c.Name())
}

func (c *Cowork) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return hookruntime.EncodeStandardResult(event.HookName.String(), result)
}
