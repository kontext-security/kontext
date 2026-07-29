package risk

import (
	"encoding/json"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/decision"
	"github.com/kontext-security/kontext-cli/internal/providerpolicy"
)

type HookEvent struct {
	SessionID     string         `json:"session_id"`
	Agent         string         `json:"agent,omitempty"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name,omitempty"`
	ToolInput     map[string]any `json:"tool_input,omitempty"`
	ToolResponse  map[string]any `json:"tool_response,omitempty"`
	ToolUseID     string         `json:"tool_use_id,omitempty"`
	CWD           string         `json:"cwd,omitempty"`
	Timestamp     time.Time      `json:"timestamp,omitempty"`
}

type EventType string

const (
	EventCredentialAccess             EventType = "credential_access"
	EventDirectProviderAPICall        EventType = "direct_provider_api_call"
	EventDestructiveProviderOperation EventType = "destructive_provider_operation"
	EventManagedToolCall              EventType = "managed_tool_call"
	EventNormalToolCall               EventType = "normal_tool_call"
	EventUnknown                      EventType = "unknown"
)

const (
	DecisionAllow = decision.Allow
	DecisionDeny  = decision.Deny
)

type Decision = decision.Decision

type AuthorizationDecision string

const (
	AuthorizationDecisionAllow  AuthorizationDecision = "ALLOW"
	AuthorizationDecisionDeny   AuthorizationDecision = "DENY"
	AuthorizationDecisionModify AuthorizationDecision = "MODIFY"
	AuthorizationDecisionStepUp AuthorizationDecision = "STEP_UP"
	AuthorizationDecisionDefer  AuthorizationDecision = "DEFER"
)

const (
	DecisionStageDeterministicDeny = "deterministic_deny"
	DecisionStageJudgeAllow        = "judge_allow"
	DecisionStageJudgeDeny         = "judge_deny"
	DecisionStageJudgeFailOpen     = "judge_fail_open"
)

type RiskEvent struct {
	Type               EventType `json:"type"`
	Provider           string    `json:"provider,omitempty"`
	ProviderCategory   string    `json:"provider_category,omitempty"`
	Operation          string    `json:"operation,omitempty"`
	OperationClass     string    `json:"operation_class,omitempty"`
	ResourceClass      string    `json:"resource_class,omitempty"`
	Environment        string    `json:"environment,omitempty"`
	CredentialObserved bool      `json:"credential_observed"`
	CredentialSource   string    `json:"credential_source,omitempty"`
	DirectAPICall      bool      `json:"direct_api_call"`
	ExplicitUserIntent bool      `json:"explicit_user_intent"`
	PathClass          string    `json:"path_class,omitempty"`
	CommandSummary     string    `json:"command_summary,omitempty"`
	RequestSummary     string    `json:"request_summary,omitempty"`
	Decision           Decision  `json:"decision,omitempty"`
	ReasonCode         string    `json:"reason_code,omitempty"`
	ModelVersion       string    `json:"model_version,omitempty"`
	GuardID            string    `json:"guard_id,omitempty"`
	RiskScore          *float64  `json:"risk_score,omitempty"`
	Confidence         float64   `json:"confidence,omitempty"`
	Signals            []string  `json:"signals,omitempty"`
	DecisionStage      string    `json:"decision_stage,omitempty"`
	PolicyVersion      string    `json:"policy_version,omitempty"`
	PolicyHash         string    `json:"policy_hash,omitempty"`
	PolicyProfile      string    `json:"policy_profile,omitempty"`
	PolicyRulePack     string    `json:"policy_rule_pack,omitempty"`
	PolicyRuleID       string    `json:"policy_rule_id,omitempty"`
	PolicyRuleCategory string    `json:"policy_rule_category,omitempty"`
	PolicySignals      []string  `json:"policy_signals,omitempty"`
	JudgeRuntime       string    `json:"judge_runtime,omitempty"`
	JudgeModel         string    `json:"judge_model,omitempty"`
	JudgeDurationMs    *int64    `json:"judge_duration_ms,omitempty"`
	JudgeFailureKind   string    `json:"judge_failure_kind,omitempty"`
	JudgeRiskLevel     string    `json:"judge_risk_level,omitempty"`
	JudgeCategories    []string  `json:"judge_categories,omitempty"`
}

type RiskDecision struct {
	Decision     Decision  `json:"decision"`
	Reason       string    `json:"reason"`
	ReasonCode   string    `json:"reason_code"`
	EventID      string    `json:"event_id,omitempty"`
	RiskScore    *float64  `json:"risk_score,omitempty"`
	Threshold    *float64  `json:"threshold,omitempty"`
	ModelVersion string    `json:"model_version,omitempty"`
	GuardID      string    `json:"guard_id,omitempty"`
	RiskEvent    RiskEvent `json:"risk_event"`
	// ProviderPolicy carries the synced-policy dry-run evaluations for this
	// event, grouped per provider; each evaluation is recorded as a separate
	// request.decided ledger row.
	ProviderPolicy []ProviderPolicyEvaluations `json:"provider_policy,omitempty"`
}

// ProviderPolicyEvaluations groups one provider's synced-policy evaluations
// for an event.
type ProviderPolicyEvaluations struct {
	Provider    string                      `json:"provider"`
	Evaluations []providerpolicy.Evaluation `json:"evaluations"`
}

func MarshalInput(value map[string]any) string {
	if len(value) == 0 {
		return ""
	}
	bytes, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(bytes)
}
