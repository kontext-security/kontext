package riskclassifier

import "sync/atomic"

// LLMGate is the runtime on/off switch for the guardrail LLM. It is consulted
// per command so a remote directive takes effect without a restart, and it
// starts enabled: the flag exists to turn the LLM off, so an org that never
// sets it keeps the default behavior.
//
// Precedence is resolved by the caller — an explicit local override wins over
// the remote directive — because a developer debugging their own machine should
// not be overridden by a config refresh.
type LLMGate struct {
	// disabled rather than enabled, so the zero value is "on".
	disabled atomic.Bool
	// pinned marks a local override; remote directives are then ignored.
	pinned atomic.Bool
}

func NewLLMGate() *LLMGate { return &LLMGate{} }

// PinLocal fixes the gate to a locally configured value and makes it immune to
// remote directives.
func (g *LLMGate) PinLocal(enabled bool) {
	if g == nil {
		return
	}
	g.disabled.Store(!enabled)
	g.pinned.Store(true)
}

// SetRemote applies an org directive unless a local override is pinned.
func (g *LLMGate) SetRemote(enabled bool) {
	if g == nil || g.pinned.Load() {
		return
	}
	g.disabled.Store(!enabled)
}

// Enabled reports whether the guardrail may run.
func (g *LLMGate) Enabled() bool {
	if g == nil {
		return true
	}
	return !g.disabled.Load()
}

// ResolveLLMEnabled decides whether the guardrail may run from the org's
// persisted directive.
//
// Absent means enabled, which is deliberately the inverse of payload capture's
// fallback. Capture reverts to its privacy-safe mode whenever the endpoint
// configuration is unconfirmed, because recording content on an unverified
// directive is the harmful outcome. Here both harmful outcomes have to be
// avoided at once:
//
//   - Defaulting to off would let a transient fetch failure silently disable the
//     classifier, a degradation nobody would notice because the SVM keeps
//     producing verdicts.
//   - Ignoring a persisted off would re-enable an LLM the org explicitly
//     disabled every time the daemon restarted before reconfirming — a kill
//     switch that fails in exactly the degraded state it exists for.
//
// Reading the persisted (Configured) directive satisfies both: an explicit false
// survives restarts and unconfirmed fetches, and absence never disables.
func ResolveLLMEnabled(directive *bool) bool {
	if directive == nil {
		return true
	}
	return *directive
}
