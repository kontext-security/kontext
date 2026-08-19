package riskclassifier

import "time"

// User feedback labels — the ground truth the observe-mode records exist to
// collect. The dashboard writes them; authz-bench retrains on them.
const (
	FeedbackShouldAllow = "should_allow"
	FeedbackShouldBlock = "should_block"

	RiskTypeInputRawCommand            = "raw_command"
	RiskTypeInputStoredRedactedCommand = "stored_redacted_command"
)

// Record is one observe-mode classifier record per intercepted bash command —
// the serving contract's logging schema mapped onto the guard store. Deviations
// from the literal SERVING.md JSON are deliberate: the command is stored
// credential-redacted (the dataset leaves the machine; live secrets must not),
// and prior_commands is not duplicated per row — earlier records in the same
// session reconstruct it at read/export time.
//
// The original verdict blocks are recorded here: the embedded binary SVM and
// the local guardrail LLM. Successful risk types use their separate derived
// table; RiskTypeError retains a missing second-stage result. The LLM half is
// absent when the guardrail is off or its call failed, in which case LLMError
// says why — a missing verdict is data too.
type Record struct {
	ActionID  string `json:"action_id"`
	SessionID string `json:"session_id"`
	ToolUseID string `json:"tool_use_id,omitempty"`
	Agent     string `json:"agent,omitempty"`

	// Command is credential-redacted and length-capped, and CommandHash is the
	// SHA-256 of exactly that stored text. Hashing anything wider — the raw
	// command, or the redacted text before truncation — would turn the hash
	// into an oracle for testing guesses about the part the row omits. Verbatim
	// repeats still collide, which is all the hash is used for.
	Command          string `json:"command"`
	CommandHash      string `json:"command_hash"`
	CommandTruncated bool   `json:"command_truncated,omitempty"`

	// AgentTask is the latest user prompt seen this session (redacted), empty
	// when the daemon has not observed one.
	AgentTask string `json:"agent_task,omitempty"`

	SVM      *SVMVerdict `json:"svm,omitempty"`
	LLM      *LLMVerdict `json:"llm,omitempty"`
	LLMError string      `json:"llm_error,omitempty"`
	// RiskTypeError records advisory model load/inference degradation for an
	// eligible binary-risky shell call. A successful derived annotation lives
	// in the separate append-only risk_type_annotations table.
	RiskTypeError string `json:"risk_type_error,omitempty"`

	// Enforced stays false for v1: verdicts are logged, never applied.
	Enforced bool `json:"enforced"`

	UserFeedback string    `json:"user_feedback,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// RiskTypeRecord is an append-only derived annotation for one existing
// classifier action. It is intentionally not part of DecisionFactV1: the fact
// and its receipt stay byte-for-byte immutable while a historical action can
// gain a model-versioned annotation later.
type RiskTypeRecord struct {
	ActionID    string          `json:"action_id"`
	SessionID   string          `json:"session_id"`
	ToolUseID   string          `json:"tool_use_id,omitempty"`
	CommandHash string          `json:"command_hash"`
	InputKind   string          `json:"input_kind"`
	Verdict     RiskTypeVerdict `json:"annotation"`
	CreatedAt   time.Time       `json:"created_at"`
}
