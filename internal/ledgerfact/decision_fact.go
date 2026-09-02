// Package ledgerfact defines Decision Fact v1: the single client-authored
// request.decided record per attempted tool call. Every fact is a Cedar
// decision record — no engine field exists because no other engine decides;
// Cedar-less shapes reduce to per-row conditions the fact expresses (a
// kill-switched deployment, a missing policy, an unresolved principal,
// evaluation failures). The daemon constructs the fact once, before
// persistence and export; `tool_call_id` correlates records that describe
// the same runtime call, while the action's stable local id makes transport
// retries idempotent.
//
// The schema is mirrored from the server-side shared contract; the golden
// corpus in testdata/decision-fact-v1.json is byte-pinned on both sides so
// the two runtimes cannot drift apart silently.
package ledgerfact

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
)

// SchemaVersion identifies Decision Fact v1 on the wire.
const SchemaVersion = "decision_fact/v1"

// FixtureDigest is the SHA-256 over the raw bytes of
// testdata/decision-fact-v1.json. The server-side contract pins the same
// value, so any edit fails CI on both sides until both corpora move together.
const FixtureDigest = "5efaeebd2519dcdbafaacbe062da1d00fe6923fb3b1bc253a1ad09a3ed8c5e08"

// cacheFetchedAtLayout is the wire format for evidence.cache_fetched_at:
// millisecond precision with an explicit UTC zone, matching the corpus bytes
// exactly so golden reproduction cannot drift on fractional-second trimming.
const cacheFetchedAtLayout = "2006-01-02T15:04:05.000Z07:00"

// RiskStatus reports whether the advisory risk analysis ran for this call.
type RiskStatus string

const (
	RiskStatusEvaluated RiskStatus = "evaluated"
	RiskStatusFailed    RiskStatus = "failed"
	RiskStatusSkipped   RiskStatus = "skipped"
)

// Risk carries advisory analysis (the local LLM judge) for the same call.
// Advisory output never becomes its own decision row; it rides on the fact.
type Risk struct {
	Status      RiskStatus `json:"status"`
	Evaluator   *string    `json:"evaluator"`
	Score       *float64   `json:"score"`
	Level       *string    `json:"level"`
	Confidence  *float64   `json:"confidence"`
	Signals     []string   `json:"signals"`
	Categories  []string   `json:"categories"`
	Summary     *string    `json:"summary"`
	FailureKind *string    `json:"failure_kind"`
}

// Classifier carries the advisory bash risk annotation for the same call: a
// char-n-gram SVM embedded in the CLI, and optionally a local guardrail LLM.
// It rides on the fact rather than in a parallel column so one decision has one
// source of truth — the receipt signs the whole fact, so a nested annotation is
// tamper-evident without a hash of its own.
//
// It is advisory in the strict sense: it is computed only after the decision is
// final and nothing consults it. Field names are the shared ingest contract and
// must not be renamed on either side of the mirror.
type Classifier struct {
	SVM      *ClassifierSVM `json:"svm"`
	LLM      *ClassifierLLM `json:"llm"`
	LLMError *string        `json:"llm_error"`
	// Command is the credential-redacted command the verdicts describe, capped at
	// 8 KiB. It ships because a verdict without the text it judged cannot be
	// analysed or corrected later, and the same command already reaches the
	// ledger as the 240-byte command_summary on every action — this is that text,
	// longer, through the same redaction ruleset.
	//
	// Note it is NOT gated on payloadCaptureMode. That is a deliberate choice,
	// not an oversight: capture governs tool payload records, and this is decision
	// evidence that rides the fact. Anything that must never leave the machine has
	// to be removed by the redactor, not by this field being absent.
	Command *string `json:"command"`
	// CommandTruncated marks Command as a prefix rather than the whole command.
	// Without it a truncated command reads as a complete one, which would quietly
	// corrupt any analysis that assumes it is.
	CommandTruncated bool `json:"command_truncated"`
}

// ClassifierSVM is the embedded model's read. It always runs, so a classifier
// block without it is malformed rather than merely sparse.
type ClassifierSVM struct {
	Verdict      string  `json:"verdict"`
	Score        float64 `json:"score"`
	Threshold    float64 `json:"threshold"`
	ModelVersion string  `json:"model_version"`
}

// ClassifierLLM is the guardrail model's read, absent whenever the LLM was
// shed — unavailable, disabled, or over budget — in which case LLMError says so.
// Cached reports a local LRU hit for a byte-identical repeat; it says nothing
// about the model.
type ClassifierLLM struct {
	Verdict    string `json:"verdict"`
	Model      string `json:"model"`
	DurationMs int64  `json:"duration_ms"`
	Cached     bool   `json:"cached"`
}

// Principal is the server-resolved Cedar evaluation principal recorded as
// evidence. The wire uses snake_case; cedareval.EvaluationPrincipal is the
// camelCase GetPolicy shape, so callers convert at the boundary.
type Principal struct {
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
}

// Evidence carries typed, non-queryable Cedar audit detail. Evidence changes
// are contract changes: accepting arbitrary keys would make the Go and
// TypeScript mirrors silently disagree about what an audit-complete fact
// contains. Authority is never derived from it; `applied_mode` on the fact
// is the only authority marker.
type Evidence struct {
	ResponseVersion        *int                          `json:"response_version"`
	RequestContractVersion *int                          `json:"request_contract_version"`
	EvaluationPrincipal    *Principal                    `json:"evaluation_principal"`
	ConfiguredMode         *cedareval.RolloutMode        `json:"configured_mode"`
	DistributionState      *string                       `json:"distribution_state"`
	ContextDiagnostics     []cedareval.ContextDiagnostic `json:"context_diagnostics"`
	EngineErrorCount       int                           `json:"engine_error_count"`
	CacheFetchedAt         *string                       `json:"cache_fetched_at"`
	CacheStale             bool                          `json:"cache_stale"`
	CacheExpired           bool                          `json:"cache_expired"`
	CacheInvalid           bool                          `json:"cache_invalid"`
	EvaluatorVersion       *string                       `json:"evaluator_version"`
	EvaluationReasonCode   *cedareval.ReasonCode         `json:"evaluation_reason_code"`
	DecisionReasonCode     *cedareval.ReasonCode         `json:"decision_reason_code"`
	EffectiveReasonCode    *cedareval.ReasonCode         `json:"effective_reason_code"`
}

// DecisionFact is the one request.decided record for an attempted tool call.
// Field order matches the wire fixture layout.
type DecisionFact struct {
	SchemaVersion string `json:"schema_version"`
	// ToolCallID correlates records that describe the same runtime call:
	// the runtime's tool-use id when the runtime supplies one, otherwise an
	// id minted exactly once when the fact is built.
	ToolCallID     string  `json:"tool_call_id"`
	DecidedAt      string  `json:"decided_at"`
	TargetProvider *string `json:"target_provider"`
	ToolName       string  `json:"tool_name"`
	Operation      *string `json:"operation"`
	ResourceID     *string `json:"resource_id"`
	ParametersHash *string `json:"parameters_hash"`
	// AppliedMode records what the endpoint actually applied — the sole
	// authority marker on the fact.
	AppliedMode     cedareval.RolloutMode     `json:"applied_mode"`
	EvaluationState cedareval.EvaluationState `json:"evaluation_state"`
	// CedarAction is Cedar's three-valued verdict; nil when Cedar reached
	// no verdict.
	CedarAction *cedareval.DerivedCedarAction `json:"cedar_action"`
	// ExecutionAction is what the hook actually applied to the tool call.
	ExecutionAction cedareval.EffectiveExecutionAction `json:"execution_action"`
	// ReasonCode is the stable cause of the conclusion or failure — never
	// an authority marker.
	ReasonCode           cedareval.ReasonCode `json:"reason_code"`
	PolicyHash           *string              `json:"policy_hash"`
	DeploymentID         *string              `json:"deployment_id"`
	DeterminingPolicyIDs []string             `json:"determining_policy_ids"`
	Risk                 *Risk                `json:"risk"`
	Classifier           *Classifier          `json:"classifier"`
	Evidence             Evidence             `json:"evidence"`
}

var sha256Hex = regexp.MustCompile(`^[a-f0-9]{64}$`)

// forbiddenReasonCodes mark authority or delegation rather than the cause of
// the policy conclusion; a fact carrying one would reintroduce the ambiguity
// this contract removes.
var forbiddenReasonCodes = map[cedareval.ReasonCode]bool{
	cedareval.ReasonObserveNonAuthoritative: true,
	cedareval.ReasonRemoteDelegated:         true,
}

var validReasonCodes = map[cedareval.ReasonCode]bool{
	cedareval.ReasonPolicyDisabled:                    true,
	cedareval.ReasonPolicyEvaluated:                   true,
	cedareval.ReasonDefaultDeny:                       true,
	cedareval.ReasonExplicitForbid:                    true,
	cedareval.ReasonPermit:                            true,
	cedareval.ReasonAskDerived:                        true,
	cedareval.ReasonAskUnavailable:                    true,
	cedareval.ReasonPrincipalUnresolved:               true,
	cedareval.ReasonRequestConversionFailed:           true,
	cedareval.ReasonPolicyMissing:                     true,
	cedareval.ReasonUnsupportedResponseVersion:        true,
	cedareval.ReasonUnsupportedRequestContractVersion: true,
	cedareval.ReasonInvalidCachedPolicy:               true,
	cedareval.ReasonStaleCachedPolicy:                 true,
	cedareval.ReasonEngineError:                       true,
	cedareval.ReasonRemoteTimeout:                     true,
	cedareval.ReasonObserveNonAuthoritative:           true,
	cedareval.ReasonEnforcementNotReady:               true,
	cedareval.ReasonRemoteDelegated:                   true,
}

// evaluatedOnlyReasonCodes mirror the shared contract's
// DECISION_FACT_EVALUATED_ONLY_REASON_CODES: causes that can only arise from
// a completed Cedar evaluation (ask_unavailable from an enforced ask
// verdict). A fact whose evaluation never completed must not attribute its
// outcome to any of these — without this list, the evaluation-evidence check
// would compare the submitted reason with itself.
var evaluatedOnlyReasonCodes = map[cedareval.ReasonCode]bool{
	cedareval.ReasonPolicyEvaluated: true,
	cedareval.ReasonPermit:          true,
	cedareval.ReasonAskDerived:      true,
	cedareval.ReasonExplicitForbid:  true,
	cedareval.ReasonDefaultDeny:     true,
	cedareval.ReasonAskUnavailable:  true,
}

// evaluationFailureReasonCodes mirror the shared contract's
// POLICY_EVALUATION_FAILURE_REASON_CODES: the stable causes a failed
// evaluation may carry.
var evaluationFailureReasonCodes = map[cedareval.ReasonCode]bool{
	cedareval.ReasonRequestConversionFailed:           true,
	cedareval.ReasonPolicyMissing:                     true,
	cedareval.ReasonUnsupportedResponseVersion:        true,
	cedareval.ReasonUnsupportedRequestContractVersion: true,
	cedareval.ReasonInvalidCachedPolicy:               true,
	cedareval.ReasonStaleCachedPolicy:                 true,
	cedareval.ReasonEngineError:                       true,
	cedareval.ReasonRemoteTimeout:                     true,
}

// Validate enforces the cross-field invariants shared with the server-side
// schema. A fact that fails validation must never be persisted or exported.
func (fact DecisionFact) Validate() error {
	var problems []error
	invalid := func(format string, args ...any) {
		problems = append(problems, fmt.Errorf(format, args...))
	}

	fact.validateIdentity(invalid)
	fact.validateEnums(invalid)
	fact.validateAuthority(invalid)
	fact.validateEvidenceCoherence(invalid)
	fact.validateRisk(invalid)
	fact.validateClassifier(invalid)

	return errors.Join(problems...)
}

func (fact DecisionFact) validateIdentity(invalid func(string, ...any)) {
	if fact.SchemaVersion != SchemaVersion {
		invalid("schema_version must be %q", SchemaVersion)
	}
	if fact.ToolCallID == "" {
		invalid("tool_call_id is required")
	}
	if _, err := time.Parse(time.RFC3339Nano, fact.DecidedAt); err != nil {
		invalid("decided_at must be an RFC 3339 timestamp: %v", err)
	}
	if fact.ToolName == "" {
		invalid("tool_name is required")
	}
	for name, value := range map[string]*string{
		"target_provider": fact.TargetProvider,
		"operation":       fact.Operation,
		"resource_id":     fact.ResourceID,
	} {
		if value != nil && *value == "" {
			invalid("%s must be null or non-empty", name)
		}
	}
	for name, value := range map[string]*string{
		"parameters_hash": fact.ParametersHash,
		"policy_hash":     fact.PolicyHash,
		"deployment_id":   fact.DeploymentID,
	} {
		if value != nil && !sha256Hex.MatchString(*value) {
			invalid("%s must be null or lowercase sha-256 hex", name)
		}
	}
	for _, policyID := range fact.DeterminingPolicyIDs {
		if policyID == "" {
			invalid("determining_policy_ids must not contain empty ids")
		}
	}
}

func (fact DecisionFact) validateEnums(invalid func(string, ...any)) {
	switch fact.AppliedMode {
	case cedareval.RolloutModeDisabled, cedareval.RolloutModeObserve, cedareval.RolloutModeEnforce:
	default:
		invalid("applied_mode %q is not part of the contract", fact.AppliedMode)
	}
	switch fact.EvaluationState {
	case cedareval.EvaluationStateEvaluated, cedareval.EvaluationStateNotEvaluated,
		cedareval.EvaluationStateFailed, cedareval.EvaluationStatePrincipalUnresolved:
	default:
		invalid("evaluation_state %q is not part of the contract", fact.EvaluationState)
	}
	if fact.CedarAction != nil {
		switch *fact.CedarAction {
		case cedareval.DerivedCedarActionAllow, cedareval.DerivedCedarActionDeny, cedareval.DerivedCedarActionAsk:
		default:
			invalid("cedar_action %q is not part of the contract", *fact.CedarAction)
		}
	}
	switch fact.ExecutionAction {
	case cedareval.EffectiveExecutionActionAllow, cedareval.EffectiveExecutionActionDeny:
	default:
		invalid("execution_action %q is not part of the contract", fact.ExecutionAction)
	}
	if forbiddenReasonCodes[fact.ReasonCode] {
		invalid("reason_code carries the outcome cause; authority is applied_mode")
	}
	if !validReasonCodes[fact.ReasonCode] {
		invalid("reason_code %q is not part of the contract", fact.ReasonCode)
	}
	if fact.Evidence.EvaluationPrincipal != nil {
		principal := fact.Evidence.EvaluationPrincipal
		if principal.EntityType != cedareval.PrincipalEntityType && principal.EntityType != cedareval.EndpointEntityTypeV2 {
			invalid("evaluation_principal entity_type is not supported")
		}
		if principal.EntityID == "" || len(principal.EntityID) > 1024 {
			invalid("evaluation_principal entity_id must be 1..1024 bytes")
		}
	}
	for _, diagnostic := range fact.Evidence.ContextDiagnostics {
		if diagnostic.Code == "" {
			invalid("context_diagnostics entries require a code")
		}
	}
	if fact.Evidence.EngineErrorCount < 0 {
		invalid("engine_error_count must be non-negative")
	}
	for name, version := range map[string]*int{
		"response_version":         fact.Evidence.ResponseVersion,
		"request_contract_version": fact.Evidence.RequestContractVersion,
	} {
		if version != nil && *version <= 0 {
			invalid("%s must be null or positive", name)
		}
	}
	if fact.Evidence.CacheFetchedAt != nil {
		if _, err := time.Parse(time.RFC3339Nano, *fact.Evidence.CacheFetchedAt); err != nil {
			invalid("cache_fetched_at must be null or an RFC 3339 timestamp: %v", err)
		}
	}
	if fact.Evidence.EvaluatorVersion != nil && *fact.Evidence.EvaluatorVersion == "" {
		invalid("evaluator_version must be null or non-empty")
	}
	if fact.Evidence.DistributionState != nil && *fact.Evidence.DistributionState == "" {
		invalid("distribution_state must be null or non-empty")
	}
}

func (fact DecisionFact) validateAuthority(invalid func(string, ...any)) {
	if (fact.CedarAction != nil) != (fact.EvaluationState == cedareval.EvaluationStateEvaluated) {
		invalid("cedar_action is present exactly when Cedar evaluated")
	}
	if fact.EvaluationState == cedareval.EvaluationStateEvaluated {
		if fact.PolicyHash == nil || fact.DeploymentID == nil {
			invalid("an evaluated fact must carry its policy provenance")
		}
		if fact.CedarAction != nil && *fact.CedarAction == cedareval.DerivedCedarActionAllow &&
			len(fact.DeterminingPolicyIDs) == 0 {
			invalid("a Cedar allow requires a determining permit")
		}
		if !determiningPolicyIDsCanonical(fact.DeterminingPolicyIDs) {
			invalid("determining policy ids must be unique and ordered by UTF-8 bytes")
		}
	}
	if fact.AppliedMode == cedareval.RolloutModeDisabled {
		// Non-evaluating deployment: nothing evaluated, nothing decided.
		if fact.EvaluationState != cedareval.EvaluationStateNotEvaluated {
			invalid("a disabled deployment records no Cedar evaluation")
		}
		if fact.ReasonCode != cedareval.ReasonPolicyDisabled && fact.ReasonCode != cedareval.ReasonPolicyMissing {
			invalid("a non-evaluating deployment records whether policy was disabled or missing")
		}
		if fact.PolicyHash != nil || fact.DeploymentID != nil || len(fact.DeterminingPolicyIDs) > 0 {
			invalid("a disabled deployment carries no policy provenance")
		}
		configured := fact.Evidence.ConfiguredMode
		switch fact.ReasonCode {
		case cedareval.ReasonPolicyDisabled:
			if configured == nil || *configured != cedareval.RolloutModeDisabled {
				invalid("configured mode distinguishes an explicit kill switch from a missing policy")
			}
		case cedareval.ReasonPolicyMissing:
			if configured != nil {
				invalid("configured mode distinguishes an explicit kill switch from a missing policy")
			}
		}
	}
	if fact.ExecutionAction == cedareval.EffectiveExecutionActionDeny &&
		fact.AppliedMode != cedareval.RolloutModeEnforce {
		// Only an applied Cedar enforce verdict can deny execution; every
		// other posture observes.
		invalid("only an enforce deployment can deny execution")
	}
	if fact.AppliedMode == cedareval.RolloutModeEnforce {
		if fact.EvaluationState != cedareval.EvaluationStateEvaluated {
			// Fail closed: enforce without a completed evaluation always denies.
			if fact.ExecutionAction != cedareval.EffectiveExecutionActionDeny {
				invalid("enforce fails closed when Cedar did not evaluate")
			}
		} else {
			expected := cedareval.EffectiveExecutionActionDeny
			if fact.CedarAction != nil && *fact.CedarAction == cedareval.DerivedCedarActionAllow {
				expected = cedareval.EffectiveExecutionActionAllow
			}
			if fact.ExecutionAction != expected {
				invalid("enforce applies the Cedar verdict (ask fails closed to deny)")
			}
		}
	}
}

func (fact DecisionFact) validateEvidenceCoherence(invalid func(string, ...any)) {
	if fact.EvaluationState != cedareval.EvaluationStateEvaluated &&
		evaluatedOnlyReasonCodes[fact.ReasonCode] {
		invalid("a fact without a completed evaluation cannot cite a Cedar verdict as its cause")
	}
	if fact.EvaluationState == cedareval.EvaluationStatePrincipalUnresolved &&
		fact.ReasonCode != cedareval.ReasonPrincipalUnresolved {
		invalid("an unresolved principal is its own cause")
	}

	expectedEvaluationReason := fact.ReasonCode
	if fact.EvaluationState == cedareval.EvaluationStateEvaluated {
		expectedEvaluationReason = cedareval.ReasonPolicyEvaluated
	}
	if !reasonCodePointerEquals(fact.Evidence.EvaluationReasonCode, expectedEvaluationReason) {
		invalid("evaluation evidence must agree with the evaluation state")
	}

	var expectedDecisionReason *cedareval.ReasonCode
	if fact.EvaluationState == cedareval.EvaluationStateEvaluated && fact.CedarAction != nil {
		var code cedareval.ReasonCode
		switch *fact.CedarAction {
		case cedareval.DerivedCedarActionAllow:
			code = cedareval.ReasonPermit
		case cedareval.DerivedCedarActionAsk:
			code = cedareval.ReasonAskDerived
		case cedareval.DerivedCedarActionDeny:
			code = cedareval.ReasonExplicitForbid
			if len(fact.DeterminingPolicyIDs) == 0 {
				code = cedareval.ReasonDefaultDeny
			}
		}
		expectedDecisionReason = &code
	}
	switch {
	case expectedDecisionReason == nil:
		if fact.Evidence.DecisionReasonCode != nil {
			invalid("decision evidence must agree with the Cedar verdict")
		}
	default:
		if !reasonCodePointerEquals(fact.Evidence.DecisionReasonCode, *expectedDecisionReason) {
			invalid("decision evidence must agree with the Cedar verdict")
		}
	}

	expectedCause := expectedEvaluationReason
	if expectedDecisionReason != nil {
		expectedCause = *expectedDecisionReason
	}
	if fact.CedarAction != nil && *fact.CedarAction == cedareval.DerivedCedarActionAsk &&
		fact.AppliedMode == cedareval.RolloutModeEnforce {
		expectedCause = cedareval.ReasonAskUnavailable
	}
	if fact.ReasonCode != expectedCause {
		invalid("reason_code must be the stable cause of this conclusion")
	}

	switch fact.AppliedMode {
	case cedareval.RolloutModeObserve:
		// effective_reason_code answers "why did the execution outcome
		// hold?" — in observe mode always the authority marker, for every
		// evaluation outcome including an unresolved principal. The cause
		// stays recorded in evaluation_state, reason_code and
		// evidence.evaluation_reason_code; per-cause exceptions here would
		// diverge from the decision-mapping corpus the evaluator follows.
		if !reasonCodePointerEquals(fact.Evidence.EffectiveReasonCode, cedareval.ReasonObserveNonAuthoritative) {
			invalid("effective evidence must agree with the applied mode")
		}
	case cedareval.RolloutModeDisabled:
		if fact.Evidence.EffectiveReasonCode != nil {
			invalid("effective evidence must agree with the applied mode")
		}
	case cedareval.RolloutModeEnforce:
		if !reasonCodePointerEquals(fact.Evidence.EffectiveReasonCode, fact.ReasonCode) {
			invalid("effective evidence must agree with the applied mode")
		}
	}

	if fact.EvaluationState == cedareval.EvaluationStateFailed &&
		!evaluationFailureReasonCodes[fact.ReasonCode] {
		invalid("a failed evaluation requires a stable failure reason")
	}

	carriesDeployment := fact.PolicyHash != nil && fact.DeploymentID != nil
	evidenceCarriesDeployment := fact.Evidence.ResponseVersion != nil &&
		fact.Evidence.RequestContractVersion != nil &&
		fact.Evidence.EvaluatorVersion != nil
	if carriesDeployment != evidenceCarriesDeployment {
		invalid("deployment provenance and evaluator provenance must be present together")
	}
	if fact.EvaluationState == cedareval.EvaluationStateEvaluated &&
		fact.Evidence.EvaluationPrincipal == nil {
		invalid("an evaluated fact must identify its Cedar principal")
	}
	if fact.EvaluationState == cedareval.EvaluationStatePrincipalUnresolved &&
		fact.Evidence.EvaluationPrincipal != nil {
		invalid("an unresolved principal cannot carry principal evidence")
	}
}

// validateClassifier pins the annotation's shape. The SVM is embedded and
// always runs, so its absence means the block was assembled wrong rather than
// that a model was unavailable — the LLM is the failable half, and its absence
// is recorded in llm_error instead. Scores are unbounded (a signed decision
// margin, not a probability), so only finiteness is checked; JSON cannot carry
// NaN, and a fact that cannot marshal must fail here rather than at export.
func (fact DecisionFact) validateClassifier(invalid func(string, ...any)) {
	classifier := fact.Classifier
	if classifier == nil {
		return
	}
	if classifier.LLMError != nil && *classifier.LLMError == "" {
		invalid("classifier.llm_error must be null or non-empty")
	}
	if classifier.Command != nil && *classifier.Command == "" {
		invalid("classifier.command must be null or non-empty")
	}
	if classifier.Command == nil && classifier.CommandTruncated {
		invalid("classifier.command_truncated has no meaning without a command")
	}
	svm := classifier.SVM
	if svm == nil {
		invalid("classifier requires an svm verdict")
	} else {
		if svm.Verdict == "" {
			invalid("classifier.svm.verdict must not be empty")
		}
		if svm.ModelVersion == "" {
			invalid("classifier.svm.model_version must not be empty")
		}
		for name, value := range map[string]float64{
			"classifier.svm.score":     svm.Score,
			"classifier.svm.threshold": svm.Threshold,
		} {
			if math.IsNaN(value) || math.IsInf(value, 0) {
				invalid("%s must be finite", name)
			}
		}
	}
	if llm := classifier.LLM; llm != nil {
		if llm.Verdict == "" {
			invalid("classifier.llm.verdict must not be empty")
		}
		if llm.Model == "" {
			invalid("classifier.llm.model must not be empty")
		}
		if llm.DurationMs < 0 {
			invalid("classifier.llm.duration_ms must not be negative")
		}
	}
}

func (fact DecisionFact) validateRisk(invalid func(string, ...any)) {
	risk := fact.Risk
	if risk == nil {
		return
	}
	switch risk.Status {
	case RiskStatusEvaluated, RiskStatusFailed, RiskStatusSkipped:
	default:
		invalid("risk.status %q is not part of the contract", risk.Status)
	}
	for name, score := range map[string]*float64{
		"risk.score":      risk.Score,
		"risk.confidence": risk.Confidence,
	} {
		if score != nil && (math.IsNaN(*score) || math.IsInf(*score, 0) || *score < 0 || *score > 1) {
			invalid("%s must be within [0, 1]", name)
		}
	}
	for _, entry := range append(append([]string{}, risk.Signals...), risk.Categories...) {
		if entry == "" {
			invalid("risk signals and categories must not contain empty entries")
		}
	}
	if risk.Evaluator != nil && *risk.Evaluator == "" {
		invalid("risk.evaluator must be null or non-empty")
	}
	if risk.FailureKind != nil && *risk.FailureKind == "" {
		invalid("risk.failure_kind must be null or non-empty")
	}

	switch risk.Status {
	case RiskStatusEvaluated:
		if risk.Evaluator == nil {
			invalid("evaluated risk requires an evaluator")
		}
		if risk.FailureKind != nil {
			invalid("evaluated risk cannot carry a failure")
		}
	case RiskStatusFailed, RiskStatusSkipped:
		hasResult := risk.Score != nil || risk.Level != nil || risk.Confidence != nil ||
			len(risk.Signals) > 0 || len(risk.Categories) > 0
		if hasResult {
			invalid("%s risk cannot carry evaluation results", risk.Status)
		}
		if risk.Status == RiskStatusFailed {
			// Summary is deliberately NOT a result here: on a failed run
			// advisoryRisk records the human-readable failure explanation in
			// it. Scores, levels, signals and categories stay forbidden above.
			if risk.Evaluator == nil || risk.FailureKind == nil {
				invalid("failed risk requires evaluator and failure_kind")
			}
		} else if risk.Evaluator != nil || risk.FailureKind != nil || risk.Summary != nil {
			invalid("skipped risk carries no evaluator, failure, or result")
		}
	}
}

// determiningPolicyIDsCanonical reports whether the ids are unique and
// ordered by UTF-8 bytes (Go string comparison is byte-wise, matching the
// shared contract's compareUtf8Bytes).
func determiningPolicyIDsCanonical(ids []string) bool {
	if !sort.StringsAreSorted(ids) {
		return false
	}
	for index := 1; index < len(ids); index++ {
		if ids[index] == ids[index-1] {
			return false
		}
	}
	return true
}

func reasonCodePointerEquals(value *cedareval.ReasonCode, expected cedareval.ReasonCode) bool {
	return value != nil && *value == expected
}
