// Package devin registers the Devin agent adapter.
package devin

import (
	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/hookruntime"
)

func init() {
	agent.Register(&Devin{})
}

type Devin struct{}

func (d *Devin) Name() string { return "devin" }

func (d *Devin) DecodeHookInput(input []byte) (hook.Event, error) {
	return hookruntime.DecodeDevinEvent(input, d.Name())
}

func (d *Devin) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return hookruntime.EncodeDevinResult(event.HookName.String(), result)
}
