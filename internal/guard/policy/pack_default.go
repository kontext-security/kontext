package policy

import "github.com/kontext-security/kontext-cli/internal/guard/risk"

func DefaultRulePack() RulePack {
	return RulePack{
		ID:      DefaultRulePackID,
		Version: "v1",
		Rules: []Rule{
			{
				ID:             "guard.destructive_persistent_resource.v1",
				Category:       CategoryDestructivePersistentResource,
				ReasonCode:     "destructive_operation_without_intent",
				Reason:         "destructive persistent-resource operation requires explicit user intent",
				NonBypassable:  true,
				MatchedSignals: []string{"destructive_verb", "persistent_resource"},
				When: func(event risk.RiskEvent) bool {
					return event.Type == risk.EventDestructiveProviderOperation &&
						risk.IsPersistentResourceClass(event.ResourceClass) &&
						!event.ExplicitUserIntent
				},
			},
			{
				ID:             "guard.direct_infra_api_with_credentials.v1",
				Category:       CategoryDirectInfraAPIWithCredentials,
				ReasonCode:     "direct_infra_api_with_credential",
				Reason:         "direct infrastructure API call included credential material",
				NonBypassable:  true,
				MatchedSignals: []string{"direct_provider_api", "credential_observed"},
				When: func(event risk.RiskEvent) bool {
					return event.Type == risk.EventDirectProviderAPICall &&
						event.ProviderCategory == "infrastructure" &&
						event.CredentialObserved
				},
			},
			{
				ID:             "guard.production_mutation.v1",
				Category:       CategoryProductionMutation,
				ReasonCode:     "production_mutation",
				Reason:         "production mutation flagged by deterministic guardrails",
				MatchedSignals: []string{"production", "mutation"},
				When: func(event risk.RiskEvent) bool {
					return event.Environment == "production" &&
						event.OperationClass != "" &&
						event.OperationClass != "unknown" &&
						event.OperationClass != "read"
				},
			},
			{
				ID:             "guard.credential_access.v1",
				Category:       CategoryCredentialAccess,
				ReasonCode:     "credential_access_without_intent",
				Reason:         "credential access flagged by deterministic guardrails",
				MatchedSignals: []string{"credential_path", "shell_credential_access", "credential_observed"},
				When: func(event risk.RiskEvent) bool {
					return event.Type == risk.EventCredentialAccess && !event.ExplicitUserIntent
				},
			},
			{
				ID:             "guard.unknown_high_risk.v1",
				Category:       CategoryUnknownHighRiskCommand,
				ReasonCode:     "unknown_high_risk_command",
				Reason:         "unknown high-risk command blocked by strict deterministic policy",
				MatchedSignals: []string{"unknown_high_risk"},
				When: func(event risk.RiskEvent) bool {
					return event.Type == risk.EventUnknown
				},
			},
		},
	}
}
