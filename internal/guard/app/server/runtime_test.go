package server

import (
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/hook"
)

func TestHookResultStampsEnforceForAuthoritativeCedarDecision(t *testing.T) {
	decision := risk.RiskDecision{
		Decision: risk.DecisionDeny,
		Cedar:    &risk.CedarEvidence{AppliedRolloutMode: cedareval.RolloutModeEnforce},
	}
	result := hookResultFromRiskDecision(decision)
	if result.Mode != "enforce" {
		t.Fatalf("result mode = %q, want enforce stamp for authoritative Cedar decision", result.Mode)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("result decision = %q, want deny", result.Decision)
	}
}

func TestHookResultLeavesModeUnstampedWithoutCedarAuthority(t *testing.T) {
	for name, decision := range map[string]risk.RiskDecision{
		"no cedar evidence":  {Decision: risk.DecisionAllow},
		"observe evaluation": {Decision: risk.DecisionAllow, Cedar: &risk.CedarEvidence{AppliedRolloutMode: cedareval.RolloutModeObserve}},
	} {
		t.Run(name, func(t *testing.T) {
			if result := hookResultFromRiskDecision(decision); result.Mode != "" {
				t.Fatalf("result mode = %q, want unstamped", result.Mode)
			}
		})
	}
}
