package claude

import (
	"github.com/kontext-security/kontext/internal/agent"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/hookruntime"
)

func init() {
	agent.Register(&Claude{})
}

type Claude struct{}

func (c *Claude) Name() string { return "claude" }

func (c *Claude) Aliases() []string { return []string{"claude-code"} }

func (c *Claude) DecodeHookInput(input []byte) (hook.Event, error) {
	return hookruntime.DecodeClaudeEvent(input, c.Name())
}

func (c *Claude) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return hookruntime.EncodeClaudeResult(event.HookName.String(), result)
}
