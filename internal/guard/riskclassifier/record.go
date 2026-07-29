package riskclassifier

import "time"

// User feedback labels — the ground truth the observe-mode records exist to
// collect. The dashboard writes them; authz-bench retrains on them.
const (
	FeedbackShouldAllow = "should_allow"
	FeedbackShouldBlock = "should_block"
)

// Record is one observe-mode classifier record per intercepted bash command —
// the serving contract's logging schema mapped onto the guard store. Deviations
// from the literal SERVING.md JSON are deliberate: the command is stored
// credential-redacted (the dataset leaves the machine; live secrets must not),
// and prior_commands is not duplicated per row — earlier records in the same
// session reconstruct it at read/export time.
//
// v1 records the SVM only. The contract's second opinion (a small local LLM
// prompted for RISKY/SAFE) is deferred: the model choice is still moving, and
// the local judge already owns the LLM half of the decision path.
type Record struct {
	ActionID  string `json:"action_id"`
	SessionID string `json:"session_id"`
	ToolUseID string `json:"tool_use_id,omitempty"`
	Agent     string `json:"agent,omitempty"`

	// Command is credential-redacted and length-capped; CommandHash is the
	// SHA-256 of the raw command so verbatim repeats stay matchable without
	// storing the raw text.
	Command          string `json:"command"`
	CommandHash      string `json:"command_hash"`
	CommandTruncated bool   `json:"command_truncated,omitempty"`

	// AgentTask is the latest user prompt seen this session (redacted), empty
	// when the daemon has not observed one.
	AgentTask string `json:"agent_task,omitempty"`

	SVM *SVMVerdict `json:"svm,omitempty"`

	// Enforced stays false for v1: verdicts are logged, never applied.
	Enforced bool `json:"enforced"`

	UserFeedback string    `json:"user_feedback,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}
