// Package claude registers the Claude Code agent adapter. Claude Code's
// native hook payload is the origin of the standard hook wire format, so the
// adapter is a thin binding of that codec to the agent name "claude".
package claude

import (
	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
)

func init() {
	agent.Register(&Claude{})
}

type Claude struct{}

func (c *Claude) Name() string { return "claude" }

func (c *Claude) Aliases() []string { return []string{"claude-code"} }

func (c *Claude) DecodeHookInput(input []byte) (hook.Event, error) {
	return hookruntime.DecodeStandardEvent(input, c.Name())
}

func (c *Claude) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return hookruntime.EncodeStandardResult(event.HookName.String(), result)
}
