package ledgerfact_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/ledgerfact"
)

// fixtureMappings hand-encodes the evaluator output that produces each golden
// fixture. Everything else in BuildInput is pass-through and derived from the
// fixture fact itself; the mapping is the semantic input the builder projects.
var fixtureMappings = map[string]cedareval.DecisionMapping{
	"enforce-evaluated-allow-permit": {
		EvaluationState:          cedareval.EvaluationStateEvaluated,
		DerivedCedarAction:       cedareval.DerivedCedarActionAllow,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionAllow,
		EvaluationReasonCode:     cedareval.ReasonPolicyEvaluated,
		DecisionReasonCode:       cedareval.ReasonPermit,
		EffectiveReasonCode:      cedareval.ReasonPermit,
		DeterminingPolicyIDs:     []string{"policy0"},
	},
	"enforce-evaluated-deny-explicit-forbid": {
		EvaluationState:          cedareval.EvaluationStateEvaluated,
		DerivedCedarAction:       cedareval.DerivedCedarActionDeny,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
		EvaluationReasonCode:     cedareval.ReasonPolicyEvaluated,
		DecisionReasonCode:       cedareval.ReasonExplicitForbid,
		EffectiveReasonCode:      cedareval.ReasonExplicitForbid,
		DeterminingPolicyIDs:     []string{"policy3"},
	},
	"enforce-evaluated-deny-default-deny": {
		EvaluationState:          cedareval.EvaluationStateEvaluated,
		DerivedCedarAction:       cedareval.DerivedCedarActionDeny,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
		EvaluationReasonCode:     cedareval.ReasonPolicyEvaluated,
		DecisionReasonCode:       cedareval.ReasonDefaultDeny,
		EffectiveReasonCode:      cedareval.ReasonDefaultDeny,
		DeterminingPolicyIDs:     []string{},
	},
	"enforce-evaluated-ask-fails-closed": {
		EvaluationState:          cedareval.EvaluationStateEvaluated,
		DerivedCedarAction:       cedareval.DerivedCedarActionAsk,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
		EvaluationReasonCode:     cedareval.ReasonPolicyEvaluated,
		DecisionReasonCode:       cedareval.ReasonAskDerived,
		EffectiveReasonCode:      cedareval.ReasonAskUnavailable,
		DeterminingPolicyIDs:     []string{"policy7"},
	},
	"enforce-failed-engine-error": {
		EvaluationState:          cedareval.EvaluationStateFailed,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
		EvaluationReasonCode:     cedareval.ReasonEngineError,
		EffectiveReasonCode:      cedareval.ReasonEngineError,
		DeterminingPolicyIDs:     []string{},
	},
	"enforce-failed-request-conversion": {
		EvaluationState:          cedareval.EvaluationStateFailed,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
		EvaluationReasonCode:     cedareval.ReasonRequestConversionFailed,
		EffectiveReasonCode:      cedareval.ReasonRequestConversionFailed,
		DeterminingPolicyIDs:     []string{},
	},
	"enforce-failed-invalid-cache": {
		EvaluationState:          cedareval.EvaluationStateFailed,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
		EvaluationReasonCode:     cedareval.ReasonInvalidCachedPolicy,
		EffectiveReasonCode:      cedareval.ReasonInvalidCachedPolicy,
		DeterminingPolicyIDs:     []string{},
	},
	"enforce-not-ready": {
		EvaluationState:          cedareval.EvaluationStateNotEvaluated,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
		EvaluationReasonCode:     cedareval.ReasonEnforcementNotReady,
		EffectiveReasonCode:      cedareval.ReasonEnforcementNotReady,
		DeterminingPolicyIDs:     []string{},
	},
	"enforce-principal-unresolved": {
		EvaluationState:          cedareval.EvaluationStatePrincipalUnresolved,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
		EvaluationReasonCode:     cedareval.ReasonPrincipalUnresolved,
		EffectiveReasonCode:      cedareval.ReasonPrincipalUnresolved,
		DeterminingPolicyIDs:     []string{},
	},
	"observe-evaluated-allow-permit": {
		EvaluationState:          cedareval.EvaluationStateEvaluated,
		DerivedCedarAction:       cedareval.DerivedCedarActionAllow,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionAllow,
		EvaluationReasonCode:     cedareval.ReasonPolicyEvaluated,
		DecisionReasonCode:       cedareval.ReasonPermit,
		EffectiveReasonCode:      cedareval.ReasonObserveNonAuthoritative,
		DeterminingPolicyIDs:     []string{"policy0"},
	},
	"observe-evaluated-would-deny": {
		EvaluationState:          cedareval.EvaluationStateEvaluated,
		DerivedCedarAction:       cedareval.DerivedCedarActionDeny,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionAllow,
		EvaluationReasonCode:     cedareval.ReasonPolicyEvaluated,
		DecisionReasonCode:       cedareval.ReasonExplicitForbid,
		EffectiveReasonCode:      cedareval.ReasonObserveNonAuthoritative,
		DeterminingPolicyIDs:     []string{"policy3"},
	},
	"observe-evaluated-ask-derived": {
		EvaluationState:          cedareval.EvaluationStateEvaluated,
		DerivedCedarAction:       cedareval.DerivedCedarActionAsk,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionAllow,
		EvaluationReasonCode:     cedareval.ReasonPolicyEvaluated,
		DecisionReasonCode:       cedareval.ReasonAskDerived,
		EffectiveReasonCode:      cedareval.ReasonObserveNonAuthoritative,
		DeterminingPolicyIDs:     []string{"policy7"},
	},
	"observe-failed-engine-error": {
		EvaluationState:          cedareval.EvaluationStateFailed,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionAllow,
		EvaluationReasonCode:     cedareval.ReasonEngineError,
		EffectiveReasonCode:      cedareval.ReasonObserveNonAuthoritative,
		DeterminingPolicyIDs:     []string{},
	},
	"observe-failed-stale-cache": {
		EvaluationState:          cedareval.EvaluationStateFailed,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionAllow,
		EvaluationReasonCode:     cedareval.ReasonStaleCachedPolicy,
		EffectiveReasonCode:      cedareval.ReasonObserveNonAuthoritative,
		DeterminingPolicyIDs:     []string{},
	},
	"observe-principal-unresolved": {
		EvaluationState:          cedareval.EvaluationStatePrincipalUnresolved,
		EffectiveExecutionAction: cedareval.EffectiveExecutionActionAllow,
		EvaluationReasonCode:     cedareval.ReasonPrincipalUnresolved,
		// The mapper marks authority, not cause, in observe mode — see the
		// observe-preserves-authority-when-principal-unresolved mapping
		// fixture. The cause stays in the evaluation reason above.
		EffectiveReasonCode:  cedareval.ReasonObserveNonAuthoritative,
		DeterminingPolicyIDs: []string{},
	},
}

func TestBuildReproducesGoldenCorpus(t *testing.T) {
	fixtures, _ := loadFixtures(t)
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			var fact ledgerfact.DecisionFact
			if err := json.Unmarshal(fixture.Fact, &fact); err != nil {
				t.Fatalf("decode fixture fact: %v", err)
			}
			decidedAt, err := time.Parse(time.RFC3339Nano, fact.DecidedAt)
			if err != nil {
				t.Fatalf("parse decided_at: %v", err)
			}

			input := ledgerfact.BuildInput{
				ToolCallID:      fact.ToolCallID,
				DecidedAt:       decidedAt,
				ToolName:        fact.ToolName,
				TargetProvider:  deref(fact.TargetProvider),
				Operation:       deref(fact.Operation),
				ResourceID:      deref(fact.ResourceID),
				ParametersHash:  deref(fact.ParametersHash),
				ExecutionAction: fact.ExecutionAction,
				Risk:            fact.Risk,
			}
			if fact.AppliedMode == cedareval.RolloutModeDisabled {
				input.Disabled = ledgerfact.DisabledInput{
					ConfiguredMode:    derefRolloutMode(fact.Evidence.ConfiguredMode),
					DistributionState: deref(fact.Evidence.DistributionState),
					CacheStale:        fact.Evidence.CacheStale,
					CacheExpired:      fact.Evidence.CacheExpired,
					CacheInvalid:      fact.Evidence.CacheInvalid,
				}
			} else {
				mapping, ok := fixtureMappings[fixture.Name]
				if !ok {
					t.Fatalf("no hand-encoded mapping for fixture %q", fixture.Name)
				}
				if fact.Evidence.EvaluationPrincipal != nil {
					mapping.EvaluationPrincipal = &cedareval.EvaluationPrincipal{
						EntityType: fact.Evidence.EvaluationPrincipal.EntityType,
						EntityID:   fact.Evidence.EvaluationPrincipal.EntityID,
					}
				}
				var fetchedAt time.Time
				if fact.Evidence.CacheFetchedAt != nil {
					parsed, err := time.Parse(time.RFC3339Nano, *fact.Evidence.CacheFetchedAt)
					if err != nil {
						t.Fatalf("parse cache_fetched_at: %v", err)
					}
					fetchedAt = parsed
				}
				input.Cedar = &ledgerfact.CedarInput{
					AppliedMode:            fact.AppliedMode,
					ConfiguredMode:         derefRolloutMode(fact.Evidence.ConfiguredMode),
					DistributionState:      deref(fact.Evidence.DistributionState),
					CacheStale:             fact.Evidence.CacheStale,
					CacheExpired:           fact.Evidence.CacheExpired,
					CacheInvalid:           fact.Evidence.CacheInvalid,
					CacheFetchedAt:         fetchedAt,
					PolicyHash:             deref(fact.PolicyHash),
					DeploymentID:           deref(fact.DeploymentID),
					ResponseVersion:        derefInt(fact.Evidence.ResponseVersion),
					RequestContractVersion: derefInt(fact.Evidence.RequestContractVersion),
					EvaluatorVersion:       deref(fact.Evidence.EvaluatorVersion),
					ContextDiagnostics:     fact.Evidence.ContextDiagnostics,
					EngineErrorCount:       fact.Evidence.EngineErrorCount,
					Mapping:                mapping,
				}
			}

			built, err := ledgerfact.Build(input)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			assertFactsEqual(t, built, fixture.Fact)
		})
	}
}

func TestBuildRejectsContractViolations(t *testing.T) {
	input := ledgerfact.BuildInput{
		ToolCallID:      "toolu_invalid",
		DecidedAt:       time.Date(2026, 7, 28, 12, 0, 0, 1, time.UTC),
		ToolName:        "Bash",
		ExecutionAction: cedareval.EffectiveExecutionActionAllow,
		Cedar: &ledgerfact.CedarInput{
			// Enforce that fails open: evaluation failed but the hook allowed.
			AppliedMode:       cedareval.RolloutModeEnforce,
			ConfiguredMode:    cedareval.RolloutModeEnforce,
			DistributionState: "success",
			Mapping: cedareval.DecisionMapping{
				EvaluationState:          cedareval.EvaluationStateFailed,
				EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
				EvaluationReasonCode:     cedareval.ReasonEngineError,
				EffectiveReasonCode:      cedareval.ReasonEngineError,
			},
		},
	}
	if _, err := ledgerfact.Build(input); err == nil {
		t.Fatal("expected build to reject a fail-open enforce fact")
	}
}

func TestResolveToolCallID(t *testing.T) {
	minted := 0
	mint := func() string {
		minted++
		return "minted-id"
	}

	if got := ledgerfact.ResolveToolCallID("toolu_runtime", mint); got != "toolu_runtime" {
		t.Fatalf("runtime id not preserved: %s", got)
	}
	if minted != 0 {
		t.Fatal("mint must not run when the runtime supplies an id")
	}
	if got := ledgerfact.ResolveToolCallID("", mint); got != "minted-id" {
		t.Fatalf("minted id not used: %s", got)
	}
	if minted != 1 {
		t.Fatalf("mint ran %d times, want exactly once", minted)
	}
}

func assertFactsEqual(t *testing.T, built ledgerfact.DecisionFact, wire json.RawMessage) {
	t.Helper()
	builtJSON, err := json.Marshal(built)
	if err != nil {
		t.Fatalf("marshal built fact: %v", err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(builtJSON, &got); err != nil {
		t.Fatalf("decode built fact: %v", err)
	}
	if err := json.Unmarshal(wire, &want); err != nil {
		t.Fatalf("decode wire fact: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("built fact diverges from golden fixture\ngot:  %s\nwant: %s", builtJSON, wire)
	}
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func derefRolloutMode(mode *cedareval.RolloutMode) cedareval.RolloutMode {
	if mode == nil {
		return ""
	}
	return *mode
}

func derefInt(value *int) int {
	if value == nil {
		return 0
	}
	return *value
}

// TestBuildAcceptsRealMapperOutput pipes the actual decision mapper into
// Build instead of a hand-encoded mapping. The hand-encoded table above once
// masked a contract/mapper divergence (observe + unresolved principal built
// a fact the validator rejected); this test makes that class of divergence
// fail here first.
func TestBuildAcceptsRealMapperOutput(t *testing.T) {
	mapping, err := cedareval.MapDecision(cedareval.DecisionMappingInput{
		RolloutMode:            cedareval.RolloutModeObserve,
		CurrentAuthorityAction: cedareval.EffectiveExecutionActionAllow,
		Evaluation: cedareval.EvaluationOutcome{
			State:  cedareval.EvaluationStatePrincipalUnresolved,
			Reason: cedareval.ReasonPrincipalUnresolved,
		},
	})
	if err != nil {
		t.Fatalf("MapDecision: %v", err)
	}

	fact, err := ledgerfact.Build(ledgerfact.BuildInput{
		ToolCallID:      "toolu_real_mapper_observe_principal",
		DecidedAt:       time.Date(2026, 7, 28, 12, 0, 15, 0, time.UTC),
		ToolName:        "Bash",
		ExecutionAction: mapping.EffectiveExecutionAction,
		Cedar: &ledgerfact.CedarInput{
			AppliedMode:       cedareval.RolloutModeObserve,
			ConfiguredMode:    cedareval.RolloutModeObserve,
			DistributionState: "principal_unavailable",
			Mapping:           mapping,
		},
	})
	if err != nil {
		t.Fatalf("Build rejected real mapper output: %v", err)
	}
	if fact.Evidence.EffectiveReasonCode == nil ||
		*fact.Evidence.EffectiveReasonCode != cedareval.ReasonObserveNonAuthoritative {
		t.Fatalf(
			"effective reason = %v, want observe_non_authoritative",
			fact.Evidence.EffectiveReasonCode,
		)
	}
	if fact.ReasonCode != cedareval.ReasonPrincipalUnresolved {
		t.Fatalf("reason_code = %s, want principal_unresolved", fact.ReasonCode)
	}
}

func TestBuildDoesNotAliasCallerOwnedRiskOrDiagnostics(t *testing.T) {
	evaluator := "local"
	score := 0.2
	risk := &ledgerfact.Risk{Status: ledgerfact.RiskStatusEvaluated, Evaluator: &evaluator, Score: &score, Signals: []string{"initial"}, Categories: []string{"read"}}
	diagnostics := []cedareval.ContextDiagnostic{{Code: "null_omitted", Path: "/input"}}
	fact, err := ledgerfact.Build(ledgerfact.BuildInput{
		ToolCallID: "toolu_copy", DecidedAt: time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC), ToolName: "Read", ExecutionAction: cedareval.EffectiveExecutionActionAllow, Risk: risk,
		Cedar: &ledgerfact.CedarInput{AppliedMode: cedareval.RolloutModeObserve, ConfiguredMode: cedareval.RolloutModeObserve, DistributionState: "success", PolicyHash: strings.Repeat("a", 64), DeploymentID: strings.Repeat("b", 64), ResponseVersion: 1, RequestContractVersion: 1, EvaluatorVersion: "cedar-go/test", ContextDiagnostics: diagnostics,
			Mapping: cedareval.DecisionMapping{EvaluationState: cedareval.EvaluationStateEvaluated, EvaluationPrincipal: &cedareval.EvaluationPrincipal{EntityType: cedareval.PrincipalEntityType, EntityID: "user@example.com"}, DerivedCedarAction: cedareval.DerivedCedarActionAllow, EffectiveExecutionAction: cedareval.EffectiveExecutionActionAllow, EvaluationReasonCode: cedareval.ReasonPolicyEvaluated, DecisionReasonCode: cedareval.ReasonPermit, EffectiveReasonCode: cedareval.ReasonObserveNonAuthoritative, DeterminingPolicyIDs: []string{"permit-read"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	evaluator = "mutated"
	score = 0.9
	risk.Signals[0] = "mutated"
	diagnostics[0].Code = "mutated"
	if *fact.Risk.Evaluator != "local" || *fact.Risk.Score != 0.2 || fact.Risk.Signals[0] != "initial" || fact.Evidence.ContextDiagnostics[0].Code != "null_omitted" {
		t.Fatalf("fact retained caller-owned data: %+v", fact)
	}
}
