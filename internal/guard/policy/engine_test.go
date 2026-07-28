package policy

import (
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

func TestEngineEvaluateProfileBehavior(t *testing.T) {
	tests := []struct {
		name     string
		event    risk.RiskEvent
		profile  Profile
		decision Decision
		category RuleCategory
		reason   string
	}{
		{
			name: "direct infra API with credentials denies in relaxed",
			event: risk.RiskEvent{
				Type:               risk.EventDirectProviderAPICall,
				ProviderCategory:   "infrastructure",
				CredentialObserved: true,
				Signals:            []string{"direct_provider_api", "credential_observed"},
			},
			profile:  ProfileRelaxed,
			decision: DecisionDeny,
			category: CategoryDirectInfraAPIWithCredentials,
		},
		{
			name: "direct infra API with credentials denies in balanced",
			event: risk.RiskEvent{
				Type:               risk.EventDirectProviderAPICall,
				ProviderCategory:   "infrastructure",
				CredentialObserved: true,
			},
			profile:  ProfileBalanced,
			decision: DecisionDeny,
			category: CategoryDirectInfraAPIWithCredentials,
		},
		{
			name: "direct infra API with credentials denies in strict",
			event: risk.RiskEvent{
				Type:               risk.EventDirectProviderAPICall,
				ProviderCategory:   "infrastructure",
				CredentialObserved: true,
			},
			profile:  ProfileStrict,
			decision: DecisionDeny,
			category: CategoryDirectInfraAPIWithCredentials,
		},
		{
			name: "destructive persistent resource without explicit intent denies in relaxed",
			event: risk.RiskEvent{
				Type:          risk.EventDestructiveProviderOperation,
				ResourceClass: "database",
				Signals:       []string{"destructive_verb", "persistent_resource"},
			},
			profile:  ProfileRelaxed,
			decision: DecisionDeny,
			category: CategoryDestructivePersistentResource,
		},
		{
			name: "destructive persistent resource without explicit intent denies in balanced",
			event: risk.RiskEvent{
				Type:          risk.EventDestructiveProviderOperation,
				ResourceClass: "bucket",
			},
			profile:  ProfileBalanced,
			decision: DecisionDeny,
			category: CategoryDestructivePersistentResource,
		},
		{
			name: "destructive persistent resource without explicit intent denies in strict",
			event: risk.RiskEvent{
				Type:          risk.EventDestructiveProviderOperation,
				ResourceClass: "volume",
			},
			profile:  ProfileStrict,
			decision: DecisionDeny,
			category: CategoryDestructivePersistentResource,
		},
		{
			name: "destructive persistent resource with explicit intent allows",
			event: risk.RiskEvent{
				Type:               risk.EventDestructiveProviderOperation,
				ResourceClass:      "database",
				ExplicitUserIntent: true,
			},
			profile:  ProfileBalanced,
			decision: DecisionAllow,
		},
		{
			name: "production mutation allows in relaxed",
			event: risk.RiskEvent{
				Environment:    "production",
				OperationClass: "write",
			},
			profile:  ProfileRelaxed,
			decision: DecisionAllow,
		},
		{
			name: "production event without operation class allows",
			event: risk.RiskEvent{
				Environment: "production",
			},
			profile:  ProfileBalanced,
			decision: DecisionAllow,
		},
		{
			name: "production mutation denies in balanced",
			event: risk.RiskEvent{
				Environment:    "production",
				OperationClass: "write",
			},
			profile:  ProfileBalanced,
			decision: DecisionDeny,
			category: CategoryProductionMutation,
			reason:   "production mutation flagged by deterministic guardrails",
		},
		{
			name: "production mutation denies in strict",
			event: risk.RiskEvent{
				Environment:    "production",
				OperationClass: "delete",
			},
			profile:  ProfileStrict,
			decision: DecisionDeny,
			category: CategoryProductionMutation,
			reason:   "production mutation flagged by deterministic guardrails",
		},
		{
			name: "credential access without intent allows in relaxed",
			event: risk.RiskEvent{
				Type: risk.EventCredentialAccess,
			},
			profile:  ProfileRelaxed,
			decision: DecisionAllow,
		},
		{
			name: "credential access without intent denies in balanced",
			event: risk.RiskEvent{
				Type:    risk.EventCredentialAccess,
				Signals: []string{"credential_path"},
			},
			profile:  ProfileBalanced,
			decision: DecisionDeny,
			category: CategoryCredentialAccess,
			reason:   "credential access flagged by deterministic guardrails",
		},
		{
			name: "credential access without intent denies in strict",
			event: risk.RiskEvent{
				Type: risk.EventCredentialAccess,
			},
			profile:  ProfileStrict,
			decision: DecisionDeny,
			category: CategoryCredentialAccess,
			reason:   "credential access flagged by deterministic guardrails",
		},
		{
			name: "unknown high-risk command allows in relaxed",
			event: risk.RiskEvent{
				Type: risk.EventUnknown,
			},
			profile:  ProfileRelaxed,
			decision: DecisionAllow,
		},
		{
			name: "unknown high-risk command allows in balanced",
			event: risk.RiskEvent{
				Type: risk.EventUnknown,
			},
			profile:  ProfileBalanced,
			decision: DecisionAllow,
		},
		{
			name: "unknown high-risk command denies in strict",
			event: risk.RiskEvent{
				Type:    risk.EventUnknown,
				Signals: []string{"unknown_high_risk"},
			},
			profile:  ProfileStrict,
			decision: DecisionDeny,
			category: CategoryUnknownHighRiskCommand,
			reason:   "unknown high-risk command blocked by strict deterministic policy",
		},
		{
			name: "normal event returns allow",
			event: risk.RiskEvent{
				Type: risk.EventNormalToolCall,
			},
			profile:  ProfileBalanced,
			decision: DecisionAllow,
		},
	}

	engine := NewEngine(DefaultRulePack())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.Profile = tt.profile

			result := engine.Evaluate(tt.event, cfg)
			if result.Decision != tt.decision {
				t.Fatalf("decision = %s, want %s", result.Decision, tt.decision)
			}
			if result.Profile != tt.profile {
				t.Fatalf("profile = %s, want %s", result.Profile, tt.profile)
			}
			if result.Stage != StageDeterministic {
				t.Fatalf("stage = %s, want %s", result.Stage, StageDeterministic)
			}
			if tt.decision == DecisionDeny {
				assertDenyMetadata(t, result, tt.category)
				if tt.reason != "" && result.Reason != tt.reason {
					t.Fatalf("reason = %q, want %q", result.Reason, tt.reason)
				}
			}
			if tt.decision == DecisionAllow && result.Matched {
				t.Fatalf("allow result should not be matched: %+v", result)
			}
		})
	}
}

func TestDenyResultIncludesMetadata(t *testing.T) {
	engine := NewEngine(DefaultRulePack())
	result := engine.Evaluate(risk.RiskEvent{
		Type:               risk.EventDirectProviderAPICall,
		ProviderCategory:   "infrastructure",
		CredentialObserved: true,
		Signals:            []string{"direct_provider_api", "credential_observed"},
	}, DefaultConfig())

	assertDenyMetadata(t, result, CategoryDirectInfraAPIWithCredentials)
	if !result.NonBypassable {
		t.Fatal("non-bypassable rule was not marked non-bypassable")
	}
	if len(result.MatchedSignals) != 2 {
		t.Fatalf("matched signals = %+v", result.MatchedSignals)
	}
}

func TestZeroValueConfigUsesDefaultNonBypassableRules(t *testing.T) {
	result := NewEngine(RulePack{}).Evaluate(risk.RiskEvent{
		Type:               risk.EventDirectProviderAPICall,
		ProviderCategory:   "infrastructure",
		CredentialObserved: true,
	}, Config{})

	if result.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want %s", result.Decision, DecisionDeny)
	}
	if !result.NonBypassable {
		t.Fatal("zero-value config should preserve default non-bypassable rules")
	}
	if result.Profile != ProfileBalanced {
		t.Fatalf("profile = %s, want %s", result.Profile, ProfileBalanced)
	}
	if result.PolicyVersion != DefaultPolicyVersion {
		t.Fatalf("policy version = %s, want %s", result.PolicyVersion, DefaultPolicyVersion)
	}
	if result.PolicyHash == "" {
		t.Fatal("policy hash is empty")
	}
	if result.RulePack != DefaultRulePackID {
		t.Fatalf("rule pack = %s, want %s", result.RulePack, DefaultRulePackID)
	}
}

func TestPartialConfigUsesDefaultNonBypassableRules(t *testing.T) {
	result := NewEngine(DefaultRulePack()).Evaluate(risk.RiskEvent{
		Type:               risk.EventDirectProviderAPICall,
		ProviderCategory:   "infrastructure",
		CredentialObserved: true,
	}, Config{Profile: ProfileBalanced})

	if result.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want %s", result.Decision, DecisionDeny)
	}
	if !result.NonBypassable {
		t.Fatal("partial config should preserve default non-bypassable rules")
	}
}

func TestExplicitNonBypassableOptOutIsHonored(t *testing.T) {
	nonBypassableRules := false
	result := NewEngine(DefaultRulePack()).Evaluate(risk.RiskEvent{
		Type:               risk.EventDirectProviderAPICall,
		ProviderCategory:   "infrastructure",
		CredentialObserved: true,
	}, Config{
		Profile:            ProfileBalanced,
		NonBypassableRules: &nonBypassableRules,
	})

	if result.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want %s", result.Decision, DecisionDeny)
	}
	if result.NonBypassable {
		t.Fatal("explicit non-bypassable opt-out should be preserved")
	}
}

func TestUnknownProfileDoesNotRelaxRules(t *testing.T) {
	result := NewEngine(DefaultRulePack()).Evaluate(risk.RiskEvent{
		Type: risk.EventUnknown,
	}, Config{Profile: "paranoid"})

	if result.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want %s", result.Decision, DecisionDeny)
	}
	if result.Category != CategoryUnknownHighRiskCommand {
		t.Fatalf("category = %s, want %s", result.Category, CategoryUnknownHighRiskCommand)
	}
}

func TestConfigValidate(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("default config should validate: %v", err)
	}
	if err := (Config{}).Validate(); err != nil {
		t.Fatalf("zero config should validate with defaults: %v", err)
	}

	nonBypassableRules := false
	if err := (Config{NonBypassableRules: &nonBypassableRules}).Validate(); err != nil {
		t.Fatalf("partial config should validate with defaults: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Profile = "paranoid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown profile should fail validation")
	}

	cfg = DefaultConfig()
	cfg.RulePack = "custom"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown rule pack should fail validation")
	}
}

func assertDenyMetadata(t *testing.T, result Result, category RuleCategory) {
	t.Helper()

	if !result.Matched {
		t.Fatal("deny result was not marked matched")
	}
	if result.RuleID == "" {
		t.Fatal("rule ID is empty")
	}
	if result.Category != category {
		t.Fatalf("category = %s, want %s", result.Category, category)
	}
	if result.ReasonCode == "" {
		t.Fatal("reason code is empty")
	}
	if result.Reason == "" {
		t.Fatal("reason is empty")
	}
	if result.RulePack == "" {
		t.Fatal("rule pack is empty")
	}
	if result.PolicyVersion == "" {
		t.Fatal("policy version is empty")
	}
	if result.PolicyHash == "" {
		t.Fatal("policy hash is empty")
	}
}
