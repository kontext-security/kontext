package cedareval

import (
	"fmt"
	"sort"
	"unicode/utf8"
)

const DecisionContractVersion = 1

type EvaluationState string

const (
	EvaluationStateNotEvaluated        EvaluationState = "not_evaluated"
	EvaluationStateEvaluated           EvaluationState = "evaluated"
	EvaluationStateFailed              EvaluationState = "failed"
	EvaluationStatePrincipalUnresolved EvaluationState = "principal_unresolved"
)

type DerivedCedarAction string

const (
	DerivedCedarActionAllow DerivedCedarAction = "allow"
	DerivedCedarActionDeny  DerivedCedarAction = "deny"
	DerivedCedarActionAsk   DerivedCedarAction = "ask"
)

type EffectiveExecutionAction string

const (
	EffectiveExecutionActionAllow EffectiveExecutionAction = "allow"
	EffectiveExecutionActionDeny  EffectiveExecutionAction = "deny"
)

type RolloutMode string

const (
	RolloutModeDisabled RolloutMode = "disabled"
	RolloutModeObserve  RolloutMode = "observe"
	RolloutModeEnforce  RolloutMode = "enforce"
)

type EvaluationProvider string

const (
	EvaluationProviderLocal  EvaluationProvider = "local"
	EvaluationProviderRemote EvaluationProvider = "remote"
)

type ReasonCode string

const (
	ReasonPolicyDisabled                    ReasonCode = "policy_disabled"
	ReasonPolicyEvaluated                   ReasonCode = "policy_evaluated"
	ReasonDefaultDeny                       ReasonCode = "default_deny"
	ReasonExplicitForbid                    ReasonCode = "explicit_forbid"
	ReasonPermit                            ReasonCode = "permit"
	ReasonAskDerived                        ReasonCode = "ask_derived"
	ReasonAskUnavailable                    ReasonCode = "ask_unavailable"
	ReasonPrincipalUnresolved               ReasonCode = "principal_unresolved"
	ReasonRequestConversionFailed           ReasonCode = "request_conversion_failed"
	ReasonPolicyMissing                     ReasonCode = "policy_missing"
	ReasonUnsupportedResponseVersion        ReasonCode = "unsupported_response_version"
	ReasonUnsupportedRequestContractVersion ReasonCode = "unsupported_request_contract_version"
	ReasonInvalidCachedPolicy               ReasonCode = "invalid_cached_policy"
	ReasonStaleCachedPolicy                 ReasonCode = "stale_cached_policy"
	ReasonEngineError                       ReasonCode = "engine_error"
	ReasonRemoteTimeout                     ReasonCode = "remote_timeout"
	ReasonObserveNonAuthoritative           ReasonCode = "observe_non_authoritative"
	ReasonEnforcementNotReady               ReasonCode = "enforcement_not_ready"
	ReasonRemoteDelegated                   ReasonCode = "remote_delegated"
)

type EvaluationOutcome struct {
	State                EvaluationState `json:"state"`
	Reason               ReasonCode      `json:"reason,omitempty"`
	Decision             Decision        `json:"decision,omitempty"`
	Ask                  bool            `json:"ask,omitempty"`
	DeterminingPolicyIDs []string        `json:"determiningPolicyIds,omitempty"`
}

type DecisionMappingInput struct {
	RolloutMode            RolloutMode              `json:"rolloutMode"`
	CurrentAuthorityAction EffectiveExecutionAction `json:"currentAuthorityAction,omitempty"`
	EnforcementReady       bool                     `json:"enforcementReady,omitempty"`
	EvaluationPrincipal    *EvaluationPrincipal     `json:"evaluationPrincipal,omitempty"`
	Evaluation             EvaluationOutcome        `json:"evaluation"`
}

type DecisionMapping struct {
	EvaluationState          EvaluationState          `json:"evaluationState"`
	EvaluationPrincipal      *EvaluationPrincipal     `json:"evaluationPrincipal,omitempty"`
	CedarDecision            Decision                 `json:"cedarDecision,omitempty"`
	DerivedCedarAction       DerivedCedarAction       `json:"derivedCedarAction,omitempty"`
	EffectiveExecutionAction EffectiveExecutionAction `json:"effectiveExecutionAction"`
	EvaluationReasonCode     ReasonCode               `json:"evaluationReasonCode"`
	DecisionReasonCode       ReasonCode               `json:"decisionReasonCode,omitempty"`
	EffectiveReasonCode      ReasonCode               `json:"effectiveReasonCode"`
	DeterminingPolicyIDs     []string                 `json:"determiningPolicyIds"`
}

func MapDecision(input DecisionMappingInput) (DecisionMapping, error) {
	if err := validateDecisionMappingInput(input); err != nil {
		return DecisionMapping{}, err
	}

	principal := cloneEvaluationPrincipal(input.EvaluationPrincipal)
	if input.RolloutMode == RolloutModeDisabled {
		return DecisionMapping{
			EvaluationState:          EvaluationStateNotEvaluated,
			EvaluationPrincipal:      principal,
			EffectiveExecutionAction: input.CurrentAuthorityAction,
			EvaluationReasonCode:     ReasonPolicyDisabled,
			EffectiveReasonCode:      ReasonPolicyDisabled,
			DeterminingPolicyIDs:     []string{},
		}, nil
	}

	if input.RolloutMode == RolloutModeObserve {
		return mapObserveDecision(input, principal), nil
	}

	return mapEnforceDecision(input, principal), nil
}

func mapObserveDecision(
	input DecisionMappingInput,
	principal *EvaluationPrincipal,
) DecisionMapping {
	if input.Evaluation.State != EvaluationStateEvaluated {
		return DecisionMapping{
			EvaluationState:          input.Evaluation.State,
			EvaluationPrincipal:      principal,
			EffectiveExecutionAction: input.CurrentAuthorityAction,
			EvaluationReasonCode:     input.Evaluation.Reason,
			EffectiveReasonCode:      ReasonObserveNonAuthoritative,
			DeterminingPolicyIDs:     []string{},
		}
	}

	decision := mapEvaluatedDecision(input.Evaluation)
	decision.EvaluationPrincipal = principal
	decision.EffectiveExecutionAction = input.CurrentAuthorityAction
	decision.EffectiveReasonCode = ReasonObserveNonAuthoritative
	return decision
}

func mapEnforceDecision(
	input DecisionMappingInput,
	principal *EvaluationPrincipal,
) DecisionMapping {
	if !input.EnforcementReady {
		return DecisionMapping{
			EvaluationState:          EvaluationStateNotEvaluated,
			EvaluationPrincipal:      principal,
			EffectiveExecutionAction: EffectiveExecutionActionDeny,
			EvaluationReasonCode:     ReasonEnforcementNotReady,
			EffectiveReasonCode:      ReasonEnforcementNotReady,
			DeterminingPolicyIDs:     []string{},
		}
	}

	if input.Evaluation.State != EvaluationStateEvaluated {
		return DecisionMapping{
			EvaluationState:          input.Evaluation.State,
			EvaluationPrincipal:      principal,
			EffectiveExecutionAction: EffectiveExecutionActionDeny,
			EvaluationReasonCode:     input.Evaluation.Reason,
			EffectiveReasonCode:      input.Evaluation.Reason,
			DeterminingPolicyIDs:     []string{},
		}
	}

	decision := mapEvaluatedDecision(input.Evaluation)
	decision.EvaluationPrincipal = principal
	switch decision.DerivedCedarAction {
	case DerivedCedarActionAllow:
		decision.EffectiveExecutionAction = EffectiveExecutionActionAllow
		decision.EffectiveReasonCode = decision.DecisionReasonCode
	case DerivedCedarActionAsk:
		decision.EffectiveExecutionAction = EffectiveExecutionActionDeny
		decision.EffectiveReasonCode = ReasonAskUnavailable
	default:
		decision.EffectiveExecutionAction = EffectiveExecutionActionDeny
		decision.EffectiveReasonCode = decision.DecisionReasonCode
	}
	return decision
}

func mapEvaluatedDecision(evaluation EvaluationOutcome) DecisionMapping {
	policyIDs := canonicalPolicyIDs(evaluation.DeterminingPolicyIDs)
	result := DecisionMapping{
		EvaluationState:      EvaluationStateEvaluated,
		CedarDecision:        evaluation.Decision,
		EvaluationReasonCode: ReasonPolicyEvaluated,
		DeterminingPolicyIDs: policyIDs,
	}

	if evaluation.Decision == DecisionAllow {
		if evaluation.Ask {
			result.DerivedCedarAction = DerivedCedarActionAsk
			result.DecisionReasonCode = ReasonAskDerived
			return result
		}
		result.DerivedCedarAction = DerivedCedarActionAllow
		result.DecisionReasonCode = ReasonPermit
		return result
	}

	result.DerivedCedarAction = DerivedCedarActionDeny
	result.DecisionReasonCode = ReasonExplicitForbid
	if len(policyIDs) == 0 {
		result.DecisionReasonCode = ReasonDefaultDeny
	}
	return result
}

func validateDecisionMappingInput(input DecisionMappingInput) error {
	if err := validateMappingPrincipal(input); err != nil {
		return err
	}
	if err := validateEvaluationOutcome(input.Evaluation); err != nil {
		return err
	}

	switch input.RolloutMode {
	case RolloutModeDisabled:
		return validateDisabledMappingInput(input)
	case RolloutModeObserve:
		return validateObserveMappingInput(input)
	case RolloutModeEnforce:
		return validateEnforceMappingInput(input)
	default:
		return fmt.Errorf("cedareval: unsupported rollout mode %q", input.RolloutMode)
	}
}

func validateMappingPrincipal(input DecisionMappingInput) error {
	if input.Evaluation.State == EvaluationStatePrincipalUnresolved {
		if input.EvaluationPrincipal != nil {
			return fmt.Errorf("cedareval: unresolved principal cannot emit principal evidence")
		}
		return nil
	}
	if input.EvaluationPrincipal == nil {
		return nil
	}
	if input.EvaluationPrincipal.EntityType != PrincipalEntityType && input.EvaluationPrincipal.EntityType != EndpointEntityTypeV2 {
		return fmt.Errorf(
			"cedareval: unsupported principal entity type %q for decision contract v%d",
			input.EvaluationPrincipal.EntityType,
			DecisionContractVersion,
		)
	}
	entityIDLength := stringLength(input.EvaluationPrincipal.EntityID)
	if entityIDLength == 0 || entityIDLength > 1024 {
		return fmt.Errorf("cedareval: principal entity id must contain 1 to 1024 characters")
	}
	return nil
}

func validateEvaluationOutcome(evaluation EvaluationOutcome) error {
	switch evaluation.State {
	case EvaluationStateNotEvaluated:
		if evaluation.Reason != ReasonPolicyDisabled && evaluation.Reason != ReasonEnforcementNotReady {
			return fmt.Errorf("cedareval: invalid not-evaluated reason %q", evaluation.Reason)
		}
		return validateEmptyEngineResult(evaluation)
	case EvaluationStatePrincipalUnresolved:
		if evaluation.Reason != ReasonPrincipalUnresolved {
			return fmt.Errorf("cedareval: invalid principal-unresolved reason %q", evaluation.Reason)
		}
		return validateEmptyEngineResult(evaluation)
	case EvaluationStateFailed:
		if !isEvaluationFailureReason(evaluation.Reason) {
			return fmt.Errorf("cedareval: invalid evaluation-failure reason %q", evaluation.Reason)
		}
		return validateEmptyEngineResult(evaluation)
	case EvaluationStateEvaluated:
		return validateEvaluatedOutcome(evaluation)
	default:
		return fmt.Errorf("cedareval: unsupported evaluation state %q", evaluation.State)
	}
}

func validateEmptyEngineResult(evaluation EvaluationOutcome) error {
	hasEngineResult := evaluation.Decision != "" || evaluation.Ask || len(evaluation.DeterminingPolicyIDs) != 0
	if hasEngineResult {
		return fmt.Errorf("cedareval: evaluation state %q cannot include a Cedar result", evaluation.State)
	}
	return nil
}

func validateEvaluatedOutcome(evaluation EvaluationOutcome) error {
	if evaluation.Reason != "" {
		return fmt.Errorf("cedareval: evaluated outcome cannot include failure reason %q", evaluation.Reason)
	}
	if evaluation.Decision != DecisionAllow && evaluation.Decision != DecisionDeny {
		return fmt.Errorf("cedareval: unsupported Cedar decision %q", evaluation.Decision)
	}
	if evaluation.Decision == DecisionDeny && evaluation.Ask {
		return fmt.Errorf("cedareval: a Cedar deny cannot derive ask")
	}
	if evaluation.Decision == DecisionAllow && len(evaluation.DeterminingPolicyIDs) == 0 {
		return fmt.Errorf("cedareval: a Cedar allow requires a determining permit")
	}
	for _, policyID := range evaluation.DeterminingPolicyIDs {
		if policyID == "" || !utf8.ValidString(policyID) {
			return fmt.Errorf("cedareval: determining policy id must be non-empty valid UTF-8")
		}
	}
	return nil
}

func validateDisabledMappingInput(input DecisionMappingInput) error {
	if !isExecutionAction(input.CurrentAuthorityAction) {
		return fmt.Errorf("cedareval: disabled mode requires the current authority action")
	}
	isDisabledOutcome := input.Evaluation.State == EvaluationStateNotEvaluated &&
		input.Evaluation.Reason == ReasonPolicyDisabled
	if !isDisabledOutcome {
		return fmt.Errorf("cedareval: disabled mode must be not evaluated with policy-disabled reason")
	}
	if input.EnforcementReady {
		return fmt.Errorf("cedareval: disabled mode cannot be enforcement ready")
	}
	return nil
}

func validateObserveMappingInput(input DecisionMappingInput) error {
	if !isExecutionAction(input.CurrentAuthorityAction) {
		return fmt.Errorf("cedareval: observe mode requires the current authority action")
	}
	if input.Evaluation.State == EvaluationStateNotEvaluated {
		return fmt.Errorf("cedareval: observe mode requires an evaluation attempt")
	}
	if input.EnforcementReady {
		return fmt.Errorf("cedareval: observe mode cannot be enforcement ready")
	}
	return nil
}

func validateEnforceMappingInput(input DecisionMappingInput) error {
	if input.CurrentAuthorityAction != "" {
		return fmt.Errorf("cedareval: enforce mode cannot use a migration authority action")
	}
	if input.Evaluation.State == EvaluationStateNotEvaluated &&
		input.Evaluation.Reason == ReasonPolicyDisabled {
		return fmt.Errorf("cedareval: enforce mode cannot carry a disabled-policy reason")
	}
	isReadinessOutcome := input.Evaluation.State == EvaluationStateNotEvaluated &&
		input.Evaluation.Reason == ReasonEnforcementNotReady
	if input.EnforcementReady == isReadinessOutcome {
		return fmt.Errorf("cedareval: enforce mode must evaluate exactly when enforcement is ready")
	}
	return nil
}

func isExecutionAction(action EffectiveExecutionAction) bool {
	return action == EffectiveExecutionActionAllow || action == EffectiveExecutionActionDeny
}

func isEvaluationFailureReason(reason ReasonCode) bool {
	switch reason {
	case ReasonRequestConversionFailed,
		ReasonPolicyMissing,
		ReasonUnsupportedResponseVersion,
		ReasonUnsupportedRequestContractVersion,
		ReasonInvalidCachedPolicy,
		ReasonStaleCachedPolicy,
		ReasonEngineError,
		ReasonRemoteTimeout:
		return true
	default:
		return false
	}
}

func canonicalPolicyIDs(policyIDs []string) []string {
	unique := make(map[string]struct{}, len(policyIDs))
	for _, policyID := range policyIDs {
		unique[policyID] = struct{}{}
	}

	result := make([]string, 0, len(unique))
	for policyID := range unique {
		result = append(result, policyID)
	}
	sort.Strings(result)
	return result
}

func cloneEvaluationPrincipal(principal *EvaluationPrincipal) *EvaluationPrincipal {
	if principal == nil {
		return nil
	}
	clone := *principal
	return &clone
}
