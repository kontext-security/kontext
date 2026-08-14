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
		if _, err := p.policies.BeginPrompt(ctx, key, event.Prompt); err != nil {
			return risk.RiskDecision{
				Decision: risk.DecisionDeny, Reason: "The prompt policy could not be activated: " + err.Error(),
				ReasonCode: "prompt_policy_activation_failed",
			}, nil
		}
	case hook.HookSessionEnd:
		p.policies.EndSession(key)
	}
	return p.current.DecideHook(ctx, event)
}
