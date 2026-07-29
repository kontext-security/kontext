package risk

const PolicyVersionLaunchV0 = "guard-launch-v0"

func DecideRisk(event HookEvent) (RiskDecision, error) {
	riskEvent := NormalizeHookEvent(event)
	riskEvent.PolicyVersion = PolicyVersionLaunchV0
	if event.HookEventName != "PreToolUse" {
		riskEvent.Decision = DecisionAllow
		riskEvent.ReasonCode = "async_telemetry"
		riskEvent.DecisionStage = "async_telemetry"
		return RiskDecision{
			Decision:   DecisionAllow,
			Reason:     "async telemetry event recorded",
			ReasonCode: "async_telemetry",
			RiskEvent:  riskEvent,
		}, nil
	}

	decision := guardDecision(riskEvent)
	if decision.Decision == "" {
		decision = RiskDecision{
			Decision:   DecisionAllow,
			Reason:     "normal tool call",
			ReasonCode: "normal_tool_call",
		}
	}
	decision.RiskEvent = riskEvent
	decision.RiskEvent.Decision = decision.Decision
	decision.RiskEvent.ReasonCode = decision.ReasonCode
	decision.RiskEvent.GuardID = decision.GuardID
	decision.RiskEvent.PolicyVersion = PolicyVersionLaunchV0
	if decision.RiskEvent.DecisionStage == "" {
		switch {
		case decision.GuardID != "":
			decision.RiskEvent.DecisionStage = "deterministic"
		default:
			decision.RiskEvent.DecisionStage = "policy_allow"
		}
	}
	return decision, nil
}

func DeterministicDecision(event RiskEvent) RiskDecision {
	return guardDecision(event)
}

func guardDecision(event RiskEvent) RiskDecision {
	if event.Type == EventDestructiveProviderOperation && isPersistentResource(event.ResourceClass) && !event.ExplicitUserIntent {
		return RiskDecision{
			Decision:   DecisionDeny,
			Reason:     "destructive persistent-resource operation requires explicit user intent",
			ReasonCode: "destructive_operation_without_intent",
			GuardID:    "guard_destructive_persistent_resource",
		}
	}
	if event.Type == EventDirectProviderAPICall && event.ProviderCategory == "infrastructure" && event.CredentialObserved {
		return RiskDecision{
			Decision:   DecisionDeny,
			Reason:     "direct infrastructure API call included credential material",
			ReasonCode: "direct_infra_api_with_credential",
			GuardID:    "guard_direct_infra_api_credential",
		}
	}
	if event.Environment == "production" && event.OperationClass != "unknown" && event.OperationClass != "read" {
		return RiskDecision{
			Decision:   DecisionDeny,
			Reason:     "production mutation flagged by deterministic guardrails",
			ReasonCode: "production_mutation",
			GuardID:    "guard_production_mutation",
		}
	}
	if event.Type == EventCredentialAccess && !event.ExplicitUserIntent {
		return RiskDecision{
			Decision:   DecisionDeny,
			Reason:     "credential access flagged by deterministic guardrails",
			ReasonCode: "credential_access_without_intent",
			GuardID:    "guard_credential_access",
		}
	}
	if event.Type == EventUnknown {
		return RiskDecision{
			Decision:   DecisionDeny,
			Reason:     "unknown high-risk command flagged by deterministic guardrails",
			ReasonCode: "unknown_high_risk_command",
			GuardID:    "guard_unknown_high_risk",
		}
	}
	return RiskDecision{}
}
