package ledgeringest

import "encoding/json"

// Typed clean-v1 wire model for POST /api/v1/authorization-ledger/batches.
//
// Field names and optionality mirror the pinned contract bundle exactly;
// the transport test validates real flush bytes against the vendored batch
// schema, so a drifting tag fails CI rather than the server. Optional
// fields are omitted, never null — hence string zero values and pointer
// numerics.

// Batch is the clean v1 envelope.
type Batch struct {
	BatchVersion       string              `json:"batch_version"`
	BatchID            string              `json:"batch_id"`
	InstallationID     string              `json:"installation_id"`
	SentAt             string              `json:"sent_at"`
	Device             *Device             `json:"device,omitempty"`
	Sessions           []SessionRecord     `json:"sessions"`
	Actions            []ActionRecord      `json:"actions"`
	Receipts           []ReceiptRecord     `json:"receipts"`
	ReceiptChainAnchor *ReceiptChainAnchor `json:"receipt_chain_anchor,omitempty"`
}

type Device struct {
	Label             string `json:"label,omitempty"`
	DeploymentVersion string `json:"deployment_version,omitempty"`
	CLIVersion        string `json:"cli_version,omitempty"`
	UserEmail         string `json:"user_email,omitempty"`
}

// ReceiptChainAnchor repeats the first receipt's chain link; the empty
// string marks a chain genesis.
type ReceiptChainAnchor struct {
	PreviousReceiptHash string `json:"previous_receipt_hash"`
}

// Identity is the closed object replacing identity_context_json.
type Identity struct {
	Agent         string `json:"agent,omitempty"`
	AgentProvider string `json:"agent_provider,omitempty"`
}

type SessionRecord struct {
	ID                string    `json:"id"`
	Source            string    `json:"source"`
	Status            string    `json:"status"`
	CreatedAt         string    `json:"created_at"`
	UpdatedAt         string    `json:"updated_at"`
	RuntimeKind       string    `json:"runtime_kind,omitempty"`
	RuntimeInstanceID string    `json:"runtime_instance_id,omitempty"`
	AdapterKind       string    `json:"adapter_kind,omitempty"`
	AdapterVersion    string    `json:"adapter_version,omitempty"`
	AgentProvider     string    `json:"agent_provider,omitempty"`
	Agent             string    `json:"agent,omitempty"`
	ConversationID    string    `json:"conversation_id,omitempty"`
	TraceID           string    `json:"trace_id,omitempty"`
	PrincipalID       string    `json:"principal_id,omitempty"`
	Identity          *Identity `json:"identity,omitempty"`
	IdentityHash      string    `json:"identity_hash,omitempty"`
	PolicyVersion     string    `json:"policy_version,omitempty"`
	PolicyHash        string    `json:"policy_hash,omitempty"`
	CWD               string    `json:"cwd,omitempty"`
	Mode              string    `json:"mode,omitempty"`
	ExternalID        string    `json:"external_id,omitempty"`
	ClosedAt          string    `json:"closed_at,omitempty"`
}

// ActionContext is the closed object replacing context_json.
type ActionContext struct {
	CWD            string         `json:"cwd,omitempty"`
	HookEventName  string         `json:"hook_event_name,omitempty"`
	PayloadCapture string         `json:"payload_capture,omitempty"`
	GitHub         *ContextGitHub `json:"github,omitempty"`
}

type ContextGitHub struct {
	BranchOrRef string `json:"branch_or_ref,omitempty"`
}

type ActionRecord struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	EventType string `json:"event_type"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`

	ToolCallID       string `json:"tool_call_id,omitempty"`
	AdapterEventName string `json:"adapter_event_name,omitempty"`
	CorrelationKey   string `json:"correlation_key,omitempty"`

	ToolName       string         `json:"tool_name,omitempty"`
	Provider       string         `json:"provider,omitempty"`
	Operation      string         `json:"operation,omitempty"`
	OperationClass string         `json:"operation_class,omitempty"`
	ResourceClass  string         `json:"resource_class,omitempty"`
	ResourceID     string         `json:"resource_id,omitempty"`
	Parameters     map[string]any `json:"parameters,omitempty"`
	ParametersHash string         `json:"parameters_hash,omitempty"`

	Identity     *Identity      `json:"identity,omitempty"`
	IdentityHash string         `json:"identity_hash,omitempty"`
	Context      *ActionContext `json:"context,omitempty"`
	ContextHash  string         `json:"context_hash,omitempty"`

	PolicyID         string          `json:"policy_id,omitempty"`
	PolicyVersion    string          `json:"policy_version,omitempty"`
	PolicyHash       string          `json:"policy_hash,omitempty"`
	DecisionResult   string          `json:"decision_result,omitempty"`
	DecisionCategory string          `json:"decision_category,omitempty"`
	AdapterDecision  string          `json:"adapter_decision,omitempty"`
	ReasonCode       string          `json:"reason_code,omitempty"`
	Reason           string          `json:"reason,omitempty"`
	DecisionFact     json.RawMessage `json:"decision_fact,omitempty"`

	RiskLevel     string   `json:"risk_level,omitempty"`
	RiskScore     *float64 `json:"risk_score,omitempty"`
	RiskThreshold *float64 `json:"risk_threshold,omitempty"`
	ModelVersion  string   `json:"model_version,omitempty"`
	Confidence    *float64 `json:"confidence,omitempty"`
	MatchedRules  []string `json:"matched_rules,omitempty"`
	RiskSignals   []string `json:"risk_signals,omitempty"`

	Outcome       string `json:"outcome,omitempty"`
	OutputSummary string `json:"output_summary,omitempty"`
	OutputHash    string `json:"output_hash,omitempty"`
	ErrorRedacted string `json:"error_redacted,omitempty"`
	ToolInput     any    `json:"tool_input,omitempty"`
	ToolOutput    any    `json:"tool_output,omitempty"`

	ProposedAt  string `json:"proposed_at,omitempty"`
	DecidedAt   string `json:"decided_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
}

type ReceiptRecord struct {
	ID          string       `json:"id"`
	ActionID    string       `json:"action_id"`
	SessionID   string       `json:"session_id"`
	ReceiptType string       `json:"receipt_type"`
	Payload     any          `json:"payload"`
	Proof       ReceiptProof `json:"proof"`
	CreatedAt   string       `json:"created_at"`
}

type ReceiptProof struct {
	ReceiptHash string            `json:"receipt_hash"`
	Signature   *ReceiptSignature `json:"signature,omitempty"`
}

type ReceiptSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
}
