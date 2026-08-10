// Package primeagent registers the Prime Agent adapter. Prime Agent
// (github.com/PrimeIntellect-ai/prime-agent) exposes a first-class extension
// system with synchronous pre-tool-use callbacks; the Kontext managed
// extension maps those extension events onto the Claude Code hook-input
// format before invoking `kontext hook --agent prime-agent`. The adapter
// therefore reuses the Claude decoder/encoder and only differs in its name,
// which is recorded as the session's agent ("prime-agent") to distinguish
// Prime Agent activity in the ledger and dashboard.
package primeagent

import (
	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
)

func init() {
	agent.Register(&PrimeAgent{})
}

type PrimeAgent struct{}

func (p *PrimeAgent) Name() string { return "prime-agent" }

func (p *PrimeAgent) Aliases() []string { return []string{"primeagent"} }

func (p *PrimeAgent) DecodeHookInput(input []byte) (hook.Event, error) {
	return hookruntime.DecodeClaudeEvent(input, p.Name())
}

func (p *PrimeAgent) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return hookruntime.EncodeClaudeResult(event.HookName.String(), result)
}
