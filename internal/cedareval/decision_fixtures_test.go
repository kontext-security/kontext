package cedareval_test

import (
	"reflect"
	"sync"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
)

type decisionContractFixture struct {
	Version                   int                                  `json:"version"`
	EvaluationStates          []cedareval.EvaluationState          `json:"evaluationStates"`
	DerivedCedarActions       []cedareval.DerivedCedarAction       `json:"derivedCedarActions"`
	EffectiveExecutionActions []cedareval.EffectiveExecutionAction `json:"effectiveExecutionActions"`
	RolloutModes              []cedareval.RolloutMode              `json:"rolloutModes"`
	EvaluationProviders       []cedareval.EvaluationProvider       `json:"evaluationProviders"`
	ReasonCodes               []cedareval.ReasonCode               `json:"reasonCodes"`
}

type decisionMappingFixture struct {
	Version     int                            `json:"version"`
	Name        string                         `json:"name"`
	Description string                         `json:"description"`
	Input       cedareval.DecisionMappingInput `json:"input"`
	Expected    cedareval.DecisionMapping      `json:"expected"`
}

func TestPortableDecisionContractFixture(t *testing.T) {
	t.Parallel()

	var fixture decisionContractFixture
	readFixture(t, "decision-contract-v1.json", &fixture)

	expected := decisionContractFixture{
		Version: cedareval.DecisionContractVersion,
		EvaluationStates: []cedareval.EvaluationState{
			cedareval.EvaluationStateNotEvaluated,
			cedareval.EvaluationStateEvaluated,
			cedareval.EvaluationStateFailed,
			cedareval.EvaluationStatePrincipalUnresolved,
		},
		DerivedCedarActions: []cedareval.DerivedCedarAction{
			cedareval.DerivedCedarActionAllow,
			cedareval.DerivedCedarActionDeny,
			cedareval.DerivedCedarActionAsk,
		},
		EffectiveExecutionActions: []cedareval.EffectiveExecutionAction{
			cedareval.EffectiveExecutionActionAllow,
			cedareval.EffectiveExecutionActionDeny,
		},
		RolloutModes: []cedareval.RolloutMode{
			cedareval.RolloutModeDisabled,
			cedareval.RolloutModeObserve,
			cedareval.RolloutModeEnforce,
		},
		EvaluationProviders: []cedareval.EvaluationProvider{
			cedareval.EvaluationProviderLocal,
			cedareval.EvaluationProviderRemote,
		},
		ReasonCodes: []cedareval.ReasonCode{
			cedareval.ReasonPolicyDisabled,
			cedareval.ReasonPolicyEvaluated,
			cedareval.ReasonDefaultDeny,
			cedareval.ReasonExplicitForbid,
			cedareval.ReasonPermit,
			cedareval.ReasonAskDerived,
			cedareval.ReasonAskUnavailable,
			cedareval.ReasonPrincipalUnresolved,
			cedareval.ReasonRequestConversionFailed,
			cedareval.ReasonPolicyMissing,
			cedareval.ReasonUnsupportedResponseVersion,
			cedareval.ReasonUnsupportedRequestContractVersion,
			cedareval.ReasonInvalidCachedPolicy,
			cedareval.ReasonStaleCachedPolicy,
			cedareval.ReasonEngineError,
			cedareval.ReasonRemoteTimeout,
			cedareval.ReasonObserveNonAuthoritative,
			cedareval.ReasonEnforcementNotReady,
			cedareval.ReasonRemoteDelegated,
		},
	}
	if !reflect.DeepEqual(fixture, expected) {
		t.Fatalf("decision contract fixture = %#v, want %#v", fixture, expected)
	}
}

func TestPortableDecisionMappingFixtures(t *testing.T) {
	var fixtures []decisionMappingFixture
	readFixture(t, "decision-mapping-v1.json", &fixtures)

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			if fixture.Version != cedareval.DecisionContractVersion {
				t.Fatalf(
					"fixture version = %d, want decision contract version %d",
					fixture.Version,
					cedareval.DecisionContractVersion,
				)
			}
			result, err := cedareval.MapDecision(fixture.Input)
			if err != nil {
				t.Fatalf("MapDecision() error = %v", err)
			}
			if !reflect.DeepEqual(result, fixture.Expected) {
				t.Fatalf("MapDecision() = %#v, want %#v", result, fixture.Expected)
			}
		})
	}
}

func TestMapDecisionIsConcurrentAndDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	principal := &cedareval.EvaluationPrincipal{
		EntityType: cedareval.PrincipalEntityType,
		EntityID:   "alice@example.com",
	}
	input := cedareval.DecisionMappingInput{
		RolloutMode:         "enforce",
		EnforcementReady:    true,
		EvaluationPrincipal: principal,
		Evaluation: cedareval.EvaluationOutcome{
			State:                cedareval.EvaluationStateEvaluated,
			Decision:             cedareval.DecisionAllow,
			DeterminingPolicyIDs: []string{"z", "a", "z"},
		},
	}

	const workers = 32
	errorsChannel := make(chan error, workers)
	results := make(chan cedareval.DecisionMapping, workers)
	var waitGroup sync.WaitGroup
	for range workers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			result, err := cedareval.MapDecision(input)
			if err != nil {
				errorsChannel <- err
				return
			}
			results <- result
		}()
	}
	waitGroup.Wait()
	close(errorsChannel)
	close(results)

	for err := range errorsChannel {
		t.Errorf("MapDecision() error = %v", err)
	}
	for result := range results {
		if !reflect.DeepEqual(result.DeterminingPolicyIDs, []string{"a", "z"}) {
			t.Errorf("DeterminingPolicyIDs = %v, want [a z]", result.DeterminingPolicyIDs)
		}
		result.DeterminingPolicyIDs[0] = "mutated"
		result.EvaluationPrincipal.EntityID = "mutated@example.com"
	}

	if !reflect.DeepEqual(input.Evaluation.DeterminingPolicyIDs, []string{"z", "a", "z"}) {
		t.Fatalf("MapDecision() mutated policy ids: %v", input.Evaluation.DeterminingPolicyIDs)
	}
	if input.EvaluationPrincipal.EntityID != "alice@example.com" {
		t.Fatalf("MapDecision() mutated principal: %q", input.EvaluationPrincipal.EntityID)
	}
}
