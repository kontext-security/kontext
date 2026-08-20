package hookruntime

import (
	"github.com/kontext-security/kontext/internal/hook"
)

// AuthoritativeEnforce reports whether a result carries the enforce stamp
// with an actionable decision. Only such results may block a tool call; a
// stamp without a real decision is never authoritative.
func AuthoritativeEnforce(result hook.Result) bool {
	return result.Mode == string(ModeEnforce) &&
		(result.Decision == hook.DecisionAllow || result.Decision == hook.DecisionDeny)
}

// ObserveResult forces observe semantics: the hook never blocks, and a
// decision that would have blocked is preserved as a would-note in the
// reason. Observe is the default posture wherever a stronger one has not
// been explicitly established.
func ObserveResult(event hook.Event, result hook.Result) hook.Result {
	result.Mode = string(ModeObserve)
	if result.Decision == "" {
		result.Decision = hook.DecisionAllow
	}
	if event.HookName.CanBlock() {
		if result.Reason == "" {
			result.Reason = "no reason provided"
		}
		if result.Decision != hook.DecisionAllow {
			result.Reason = "Kontext observe mode: would " + string(result.Decision) + "; " + result.Reason
		}
	}
	result.Decision = hook.DecisionAllow
	return result
}

// ApplyRemote is the single implementation of the remote posture rule: a
// result the policy distribution made authoritative (enforce-stamped, with a
// real decision) passes through, normalized to allow on hooks that cannot
// block; everything else defaults to observe. Every hook edge must call this
// rather than reimplement the rule.
func ApplyRemote(event hook.Event, result hook.Result) hook.Result {
	if AuthoritativeEnforce(result) {
		if !event.HookName.CanBlock() {
			result.Decision = hook.DecisionAllow
		}
		return result
	}
	return ObserveResult(event, result)
}
