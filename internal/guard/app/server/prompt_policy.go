package server

import (
	"context"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/sessionpolicy"
)

type promptPolicyProvider struct {
	current  PolicyProvider
	policies *sessionpolicy.Manager
}

func newPromptPolicyProvider(current PolicyProvider, policies *sessionpolicy.Manager) PolicyProvider {
	if policies == nil {
		return current
	}
	return &promptPolicyProvider{current: current, policies: policies}
}

func (p *promptPolicyProvider) DecideHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	key := sessionpolicy.SessionKey{Provider: event.Agent, NativeSessionID: event.SessionID}
	switch hook.HookName(event.HookEventName) {
	case hook.HookUserPromptSubmit:
		snapshot, activationErr := p.policies.BeginPrompt(ctx, key, event.Prompt)
		decision, err := p.current.DecideHook(ctx, event)
		if err != nil {
			decision = risk.RiskDecision{
				Reason:     "Prompt accepted; downstream prompt evaluation was unavailable.",
				ReasonCode: "prompt_evaluation_unavailable",
			}
		}
		decision.Decision = risk.DecisionAllow
		if activationErr != nil {
			decision.Reason = "Prompt accepted; policy was not generated."
			decision.ReasonCode = "prompt_policy_generation_failed"
		} else if snapshot.State == sessionpolicy.SessionStateActive {
			decision.Reason = "Prompt accepted; policy generated."
			decision.ReasonCode = "prompt_policy_generated"
		}
		return decision, nil
	case hook.HookSessionEnd:
		p.policies.EndSession(key)
	}
	return p.current.DecideHook(ctx, event)
}
