package server

import (
	"context"

	"github.com/kontext-security/kontext/internal/guard/risk"
)

type PolicyProvider interface {
	DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error)
}

type RiskPolicyProvider struct{}

func NewRiskPolicyProvider() RiskPolicyProvider {
	return RiskPolicyProvider{}
}

func (p RiskPolicyProvider) DecideHook(_ context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	if event.HookEventName != "PreToolUse" {
		return p.asyncTelemetryDecision(event), nil
	}
	riskEvent := risk.NormalizeHookEvent(event)
	// Annotation deliberately does not happen here. This chain is only one input
	// to the decision, so annotating from inside it would both miss Cedar's
	// final answer and leave any path that does not route through this provider
	// unannotated. The runtime annotates once, after the decision is final.
	return advisoryDecision(riskEvent), nil
}

func (p RiskPolicyProvider) asyncTelemetryDecision(event risk.HookEvent) risk.RiskDecision {
	riskEvent := risk.NormalizeHookEvent(event)
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = "async_telemetry"
	riskEvent.DecisionStage = "async_telemetry"
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "async telemetry event recorded",
		ReasonCode: "async_telemetry",
		RiskEvent:  riskEvent,
	}
}

// advisoryDecision records the observation without deciding. Cedar alone decides.
func advisoryDecision(riskEvent risk.RiskEvent) risk.RiskDecision {
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = risk.DecisionStageAdvisory
	riskEvent.DecisionStage = risk.DecisionStageAdvisory
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "observed; no local analysis wired",
		ReasonCode: risk.DecisionStageAdvisory,
		RiskEvent:  riskEvent,
	}
}
