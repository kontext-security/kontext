package sqlite

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/ledgerfact"
)

// applyDecisionFact turns the legacy-shaped decided-row values into the one
// Decision Fact v1 record for this tool call: the fact's fields are written
// onto the same row (queryable mirror columns plus the complete fact JSON),
// so the single request.decided row is audit-complete on its own. No sibling
// decision rows exist for new writes.
func applyDecisionFact(action map[string]any, event risk.HookEvent, decision risk.RiskDecision, decidedAt time.Time) error {
	input := ledgerfact.BuildInput{
		ToolCallID: ledgerfact.ResolveToolCallID(event.ToolUseID, func() string {
			return "tc_" + uuid.NewString()
		}),
		DecidedAt:       decidedAt,
		ToolName:        event.ToolName,
		TargetProvider:  stringValue(action["provider"]),
		Operation:       stringValue(action["operation"]),
		ResourceID:      stringValue(action["resource_id"]),
		ParametersHash:  bareHexHash(stringValue(action["parameters_hash"])),
		ExecutionAction: executionActionFromDecision(decision.Decision),
		Risk:            advisoryRisk(decision),
	}
	if evidence := decision.Cedar; evidence != nil && cedarIsEngineOfRecord(*evidence) {
		input.Cedar = &ledgerfact.CedarInput{
			AppliedMode:            evidence.AppliedRolloutMode,
			ConfiguredMode:         evidence.ConfiguredRolloutMode,
			DistributionState:      evidence.DistributionState,
			CacheStale:             evidence.CacheStale,
			CacheExpired:           evidence.CacheExpired,
			CacheInvalid:           evidence.CacheInvalid,
			CacheFetchedAt:         evidence.CacheFetchedAt,
			PolicyHash:             evidence.PolicyHash,
			DeploymentID:           evidence.DeploymentIdentity,
			ResponseVersion:        evidence.ResponseVersion,
			RequestContractVersion: evidence.RequestContractVersion,
			EvaluatorVersion:       evidence.EvaluatorVersion,
			ContextDiagnostics:     evidence.ContextDiagnostics,
			EngineErrorCount:       evidence.EngineErrorCount,
			Mapping:                evidence.Mapping,
		}
	} else if evidence != nil {
		input.Disabled = ledgerfact.DisabledInput{
			ConfiguredMode:    evidence.ConfiguredRolloutMode,
			DistributionState: evidence.DistributionState,
			CacheStale:        evidence.CacheStale,
			CacheExpired:      evidence.CacheExpired,
			CacheInvalid:      evidence.CacheInvalid,
		}
	}

	fact, err := ledgerfact.Build(input)
	if err != nil {
		return err
	}
	factJSON, err := json.Marshal(fact)
	if err != nil {
		return fmt.Errorf("marshal decision fact: %w", err)
	}

	action["schema_version"] = ledgerfact.SchemaVersion
	action["tool_call_id"] = fact.ToolCallID
	action["applied_mode"] = string(fact.AppliedMode)
	action["evaluation_state"] = string(fact.EvaluationState)
	if fact.CedarAction != nil {
		action["cedar_action"] = string(*fact.CedarAction)
	} else {
		action["cedar_action"] = nil
	}
	action["decision_fact_json"] = string(factJSON)
	action["reason_code"] = string(fact.ReasonCode)
	if fact.AppliedMode != cedareval.RolloutModeDisabled {
		action["decision_category"] = "cedar_policy"
		action["policy_hash"] = nullIfEmptyPointer(fact.PolicyHash)
		action["policy_version"] = nullIfEmptyPointer(fact.DeploymentID)
		action["matched_rules_json"] = mustJSONText(fact.DeterminingPolicyIDs)
	}
	return mergeDecisionContext(action, fact, decision)
}

// cedarIsEngineOfRecord reports whether a usable Cedar deployment answered
// this call. Explicit disabled/no-active-policy distribution states produce
// the disabled fact shape; every other state (including principal_unavailable
// and cache failures) is Cedar answering — possibly with a failure outcome —
// and is recorded as such.
func cedarIsEngineOfRecord(evidence risk.CedarEvidence) bool {
	switch evidence.DistributionState {
	case "disabled", "no_active_policy":
		return false
	default:
		return true
	}
}

func executionActionFromDecision(decision risk.Decision) cedareval.EffectiveExecutionAction {
	// Mirrors canonicalDecisionResult: only an explicit allow executes; every
	// other verdict was applied as a deny.
	if decision == risk.DecisionAllow {
		return cedareval.EffectiveExecutionActionAllow
	}
	return cedareval.EffectiveExecutionActionDeny
}

// advisoryRisk records the local LLM judge's analysis on the fact when the
// judge ran. Deterministic guardrail output is not a risk evaluation — its
// signals stay on the row's legacy risk columns — and the authoritative
// Cedar path never runs the judge, so those calls carry no risk block.
func advisoryRisk(decision risk.RiskDecision) *ledgerfact.Risk {
	riskEvent := decision.RiskEvent
	evaluator := riskEvent.JudgeModel
	if evaluator == "" {
		evaluator = riskEvent.JudgeRuntime
	}
	if failure := string(riskEvent.JudgeFailureKind); failure != "" {
		if evaluator == "" {
			evaluator = "local_llm_judge"
		}
		failed := ledgerfact.Risk{
			Status:      ledgerfact.RiskStatusFailed,
			Evaluator:   &evaluator,
			Signals:     []string{},
			Categories:  []string{},
			FailureKind: &failure,
		}
		if summary := decision.Reason; summary != "" {
			failed.Summary = &summary
		}
		return &failed
	}
	if evaluator == "" {
		return nil
	}

	advisory := ledgerfact.Risk{
		Status:     ledgerfact.RiskStatusEvaluated,
		Evaluator:  &evaluator,
		Signals:    nonEmptyStringsOnly(riskEvent.Signals),
		Categories: nonEmptyStringsOnly(riskEvent.JudgeCategories),
	}
	if score := decision.RiskScore; score != nil && *score >= 0 && *score <= 1 {
		value := *score
		advisory.Score = &value
	}
	if level := riskEvent.JudgeRiskLevel; level != "" {
		advisory.Level = &level
	}
	if confidence := riskEvent.Confidence; confidence > 0 && confidence <= 1 {
		advisory.Confidence = &confidence
	}
	if summary := decision.Reason; summary != "" {
		advisory.Summary = &summary
	}
	return &advisory
}

func nonEmptyStringsOnly(values []string) []string {
	kept := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			kept = append(kept, value)
		}
	}
	return kept
}

// mergeDecisionContext rewrites the row's context payload so the one row
// carries the fact's evidence.
func mergeDecisionContext(action map[string]any, fact ledgerfact.DecisionFact, decision risk.RiskDecision) error {
	contextPayload := map[string]any{}
	if existing, ok := action["context_json"].(string); ok && existing != "" {
		if err := json.Unmarshal([]byte(existing), &contextPayload); err != nil {
			return fmt.Errorf("decode decided-row context: %w", err)
		}
	}
	contextPayload["policy_evidence"] = fact.Evidence
	contextJSON, contextHash := mustHashJSON(contextPayload)
	action["context_json"] = contextJSON
	action["context_hash"] = contextHash
	return nil
}

func nullIfEmptyPointer(value *string) any {
	if value == nil || *value == "" {
		return nil
	}
	return *value
}

// bareHexHash normalizes the store's historical "sha256:<hex>" hash format to
// the contract's bare lowercase hex. The legacy row column keeps its
// historical format; the fact is bare hex everywhere.
func bareHexHash(value string) string {
	return strings.TrimPrefix(value, "sha256:")
}
