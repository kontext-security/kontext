package ledgerfact

import (
	"fmt"
	"sort"
	"time"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
)

// CedarInput carries the evaluation outcome and cache/provenance detail the
// builder needs when a usable Cedar deployment answered (observe or
// enforce). It deliberately mirrors only what the fact records, so callers
// adapt their evidence type at the boundary and ledgerfact stays free of
// persistence-layer imports.
type CedarInput struct {
	// AppliedMode is what the endpoint actually applied for this call:
	// observe or enforce. Kill-switched or missing deployments use the
	// Disabled input instead (leave Cedar out of BuildInput entirely).
	AppliedMode            cedareval.RolloutMode
	ConfiguredMode         cedareval.RolloutMode
	DistributionState      string
	CacheStale             bool
	CacheExpired           bool
	CacheInvalid           bool
	CacheFetchedAt         time.Time
	PolicyHash             string
	DeploymentID           string
	ResponseVersion        int
	RequestContractVersion int
	EvaluatorVersion       string
	ContextDiagnostics     []cedareval.ContextDiagnostic
	EngineErrorCount       int
	Mapping                cedareval.DecisionMapping
}

// DisabledInput describes why no Cedar deployment answered: an explicit kill
// switch (configured mode "disabled") or a missing policy. The builder
// derives the fact's cause from it, so the two shapes cannot be conflated.
type DisabledInput struct {
	ConfiguredMode    cedareval.RolloutMode
	DistributionState string
	CacheStale        bool
	CacheExpired      bool
	CacheInvalid      bool
}

// BuildInput is everything that happened for one attempted tool call.
type BuildInput struct {
	// ToolCallID must already be resolved via ResolveToolCallID; Build
	// never generates identity, so retries that rebuild the fact stay
	// idempotent.
	ToolCallID     string
	DecidedAt      time.Time
	ToolName       string
	TargetProvider string
	Operation      string
	ResourceID     string
	ParametersHash string
	// ExecutionAction is what the hook actually applied.
	ExecutionAction cedareval.EffectiveExecutionAction
	// Cedar is present whenever a usable Cedar deployment answered
	// (observe or enforce). Nil means the deployment was kill-switched or
	// had no active policy — the disabled fact shape.
	Cedar *CedarInput
	// Disabled describes the non-evaluating deployment when Cedar is nil.
	Disabled DisabledInput
	// Risk is the advisory analysis for the same call, if any ran.
	Risk *Risk
	// Classifier is the advisory bash risk annotation, if the command was
	// scored. Supplied only after the decision is final.
	Classifier *Classifier
}

// ResolveToolCallID returns the runtime-supplied tool-use id when present and
// otherwise mints one. The result must be resolved once per attempted call,
// before the fact is built, and reused for every retry — a re-mint would make
// a retry look like a second decision.
func ResolveToolCallID(runtimeToolUseID string, mint func() string) string {
	if runtimeToolUseID != "" {
		return runtimeToolUseID
	}
	return mint()
}

// Build assembles the one decision fact for an attempted tool call and
// validates it before returning. A build error means the inputs describe an
// outcome the contract forbids; nothing may be persisted from it.
func Build(input BuildInput) (DecisionFact, error) {
	fact := DecisionFact{
		SchemaVersion:        SchemaVersion,
		ToolCallID:           input.ToolCallID,
		DecidedAt:            input.DecidedAt.UTC().Format(time.RFC3339Nano),
		TargetProvider:       nullable(input.TargetProvider),
		ToolName:             input.ToolName,
		Operation:            nullable(input.Operation),
		ResourceID:           nullable(input.ResourceID),
		ParametersHash:       nullable(input.ParametersHash),
		ExecutionAction:      input.ExecutionAction,
		DeterminingPolicyIDs: []string{},
		Risk:                 cloneRisk(input.Risk),
		Classifier:           cloneClassifier(input.Classifier),
	}

	if input.Cedar == nil {
		buildDisabledFact(&fact, input.Disabled)
	} else {
		buildCedarFact(&fact, *input.Cedar)
	}

	if err := fact.Validate(); err != nil {
		return DecisionFact{}, fmt.Errorf("decision fact violates the contract: %w", err)
	}
	return fact, nil
}

// buildDisabledFact records a call no deployment answered: nothing
// evaluated, nothing decided. The cause distinguishes an explicit kill
// switch from a missing policy via the configured rollout mode.
func buildDisabledFact(fact *DecisionFact, disabled DisabledInput) {
	fact.AppliedMode = cedareval.RolloutModeDisabled
	fact.EvaluationState = cedareval.EvaluationStateNotEvaluated
	fact.ReasonCode = cedareval.ReasonPolicyMissing
	if disabled.ConfiguredMode == cedareval.RolloutModeDisabled {
		fact.ReasonCode = cedareval.ReasonPolicyDisabled
	}
	evaluationReason := fact.ReasonCode
	fact.Evidence = Evidence{
		ConfiguredMode:       nullableRolloutMode(disabled.ConfiguredMode),
		DistributionState:    nullable(disabled.DistributionState),
		ContextDiagnostics:   []cedareval.ContextDiagnostic{},
		CacheStale:           disabled.CacheStale,
		CacheExpired:         disabled.CacheExpired,
		CacheInvalid:         disabled.CacheInvalid,
		EvaluationReasonCode: &evaluationReason,
	}
}

func buildCedarFact(fact *DecisionFact, cedar CedarInput) {
	fact.AppliedMode = cedar.AppliedMode
	fact.EvaluationState = cedar.Mapping.EvaluationState
	if cedar.Mapping.EvaluationState == cedareval.EvaluationStateEvaluated {
		action := cedar.Mapping.DerivedCedarAction
		fact.CedarAction = &action
	}
	fact.ReasonCode = factReasonCode(cedar)
	fact.PolicyHash = nullable(cedar.PolicyHash)
	fact.DeploymentID = nullable(cedar.DeploymentID)
	fact.DeterminingPolicyIDs = canonicalPolicyIDs(cedar.Mapping.DeterminingPolicyIDs)
	fact.Evidence = cedarEvidence(cedar)
}

// factReasonCode selects the stable cause of the outcome. In enforce mode
// the effective code already is the cause (an enforced ask surfaces as
// ask_unavailable). Outside enforce the effective code would be the
// authority marker observe_non_authoritative, so the fact records the
// decision cause instead — the evaluation cause when Cedar never reached a
// verdict.
func factReasonCode(cedar CedarInput) cedareval.ReasonCode {
	if cedar.AppliedMode == cedareval.RolloutModeEnforce {
		return cedar.Mapping.EffectiveReasonCode
	}
	if cedar.Mapping.EvaluationState == cedareval.EvaluationStateEvaluated {
		return cedar.Mapping.DecisionReasonCode
	}
	return cedar.Mapping.EvaluationReasonCode
}

func cedarEvidence(cedar CedarInput) Evidence {
	diagnostics := append([]cedareval.ContextDiagnostic{}, cedar.ContextDiagnostics...)
	evidence := Evidence{
		ResponseVersion:        nullableInt(cedar.ResponseVersion),
		RequestContractVersion: nullableInt(cedar.RequestContractVersion),
		EvaluationPrincipal:    factPrincipal(cedar.Mapping.EvaluationPrincipal),
		ConfiguredMode:         nullableRolloutMode(cedar.ConfiguredMode),
		DistributionState:      nullable(cedar.DistributionState),
		ContextDiagnostics:     diagnostics,
		EngineErrorCount:       cedar.EngineErrorCount,
		CacheStale:             cedar.CacheStale,
		CacheExpired:           cedar.CacheExpired,
		CacheInvalid:           cedar.CacheInvalid,
		EvaluatorVersion:       nullable(cedar.EvaluatorVersion),
		EvaluationReasonCode:   nullableReasonCode(cedar.Mapping.EvaluationReasonCode),
		DecisionReasonCode:     nullableReasonCode(cedar.Mapping.DecisionReasonCode),
		EffectiveReasonCode:    nullableReasonCode(cedar.Mapping.EffectiveReasonCode),
	}
	if !cedar.CacheFetchedAt.IsZero() {
		fetchedAt := cedar.CacheFetchedAt.UTC().Format(cacheFetchedAtLayout)
		evidence.CacheFetchedAt = &fetchedAt
	}
	return evidence
}

func cloneClassifier(classifier *Classifier) *Classifier {
	if classifier == nil {
		return nil
	}
	cloned := *classifier
	cloned.LLMError = cloneString(classifier.LLMError)
	cloned.Command = cloneString(classifier.Command)
	if classifier.SVM != nil {
		svm := *classifier.SVM
		cloned.SVM = &svm
	}
	if classifier.LLM != nil {
		llm := *classifier.LLM
		cloned.LLM = &llm
	}
	return &cloned
}

func cloneRisk(risk *Risk) *Risk {
	if risk == nil {
		return nil
	}
	cloned := *risk
	cloned.Evaluator = cloneString(risk.Evaluator)
	cloned.Score = cloneFloat64(risk.Score)
	cloned.Level = cloneString(risk.Level)
	cloned.Confidence = cloneFloat64(risk.Confidence)
	cloned.Signals = append([]string{}, risk.Signals...)
	cloned.Categories = append([]string{}, risk.Categories...)
	cloned.Summary = cloneString(risk.Summary)
	cloned.FailureKind = cloneString(risk.FailureKind)
	return &cloned
}

func cloneString(value *string) *string {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneFloat64(value *float64) *float64 {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func factPrincipal(principal *cedareval.EvaluationPrincipal) *Principal {
	if principal == nil {
		return nil
	}
	return &Principal{
		EntityType: principal.EntityType,
		EntityID:   principal.EntityID,
	}
}

// canonicalPolicyIDs returns the determining policy ids unique and ordered
// by UTF-8 bytes, as the contract requires.
func canonicalPolicyIDs(ids []string) []string {
	canonical := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		canonical = append(canonical, id)
	}
	sort.Strings(canonical)
	return canonical
}

func nullable(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func nullableInt(value int) *int {
	if value <= 0 {
		return nil
	}
	return &value
}

func nullableReasonCode(code cedareval.ReasonCode) *cedareval.ReasonCode {
	if code == "" {
		return nil
	}
	return &code
}

func nullableRolloutMode(mode cedareval.RolloutMode) *cedareval.RolloutMode {
	if mode == "" {
		return nil
	}
	return &mode
}
