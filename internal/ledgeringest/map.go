package ledgeringest

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Maps exported ledger rows (the store's map[string]any records) onto the
// typed clean-v1 wire model. This file is the single legacy->v1 name
// authority on the CLI: every rename, drop, and closed-vocabulary guard
// lives here, and the transport test validates the mapped output against
// the pinned schema bundle.
//
// Guards are deliberately drop-not-fail for optional fields: an optional
// value outside its closed vocabulary is omitted (the record stays true,
// just less detailed), while a record that cannot satisfy a *required*
// contract rule returns an error so the flush loop can isolate it instead
// of poisoning the batch.

// BatchInput carries one export page plus envelope facts.
type BatchInput struct {
	BatchID        string
	InstallationID string
	SentAt         string
	Device         *Device
	Sessions       []map[string]any
	Actions        []map[string]any
	Receipts       []map[string]any
	// AnchorPreviousReceiptHash is non-nil exactly when receipts are present;
	// the empty string marks a chain genesis.
	AnchorPreviousReceiptHash *string
}

// MapBatch converts one export page to the clean v1 envelope. Session
// lifecycle rows (session.start/session.end) are local records only — the
// clean contract carries session lifecycle via session records — so they
// are dropped from the actions array here.
func MapBatch(in BatchInput) (Batch, error) {
	batch := Batch{
		BatchVersion:   BatchVersion,
		BatchID:        in.BatchID,
		InstallationID: in.InstallationID,
		SentAt:         in.SentAt,
		Device:         in.Device,
		Sessions:       []SessionRecord{},
		Actions:        []ActionRecord{},
		Receipts:       []ReceiptRecord{},
	}
	for _, record := range in.Sessions {
		session, err := mapSession(record)
		if err != nil {
			return Batch{}, fmt.Errorf("session %s: %w", stringField(record, "id"), err)
		}
		batch.Sessions = append(batch.Sessions, session)
	}
	for _, record := range in.Actions {
		action, err := mapAction(record)
		if err != nil {
			return Batch{}, fmt.Errorf("action %s: %w", stringField(record, "id"), err)
		}
		if action == nil {
			continue
		}
		batch.Actions = append(batch.Actions, *action)
	}
	for _, record := range in.Receipts {
		receipt, err := mapReceipt(record)
		if err != nil {
			return Batch{}, fmt.Errorf("receipt %s: %w", stringField(record, "id"), err)
		}
		batch.Receipts = append(batch.Receipts, receipt)
	}
	if len(batch.Receipts) > 0 {
		if in.AnchorPreviousReceiptHash == nil {
			return Batch{}, fmt.Errorf("receipts present without a chain anchor")
		}
		batch.ReceiptChainAnchor = &ReceiptChainAnchor{
			PreviousReceiptHash: *in.AnchorPreviousReceiptHash,
		}
	}
	return batch, nil
}

const (
	eventSessionStart = "session.start"
	eventSessionEnd   = "session.end"
)

var (
	timestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$`)
	hashPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	safeIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$`)

	sessionSources     = stringSet("wrapper_owned", "daemon_observed")
	sessionModes       = stringSet("disabled", "observe", "enforce")
	actionEventTypes   = stringSet("request.proposed", "request.decided", "request.observed", "request.failed")
	actionOutcomes     = stringSet("success", "error", "not_executed")
	riskLevels         = stringSet("LOW", "MEDIUM", "HIGH", "CRITICAL")
	decisionCategories = stringSet(
		"cedar_policy", "deterministic_deny", "advisory",
		"judge_allow", "judge_deny", "judge_fail_open", "default",
	)
	captureModes = stringSet("omitted", "summary", "full")
)

func mapSession(record map[string]any) (SessionRecord, error) {
	session := SessionRecord{
		ID:                stringField(record, "id"),
		Source:            stringField(record, "source"),
		Status:            stringField(record, "status"),
		CreatedAt:         stringField(record, "created_at"),
		UpdatedAt:         stringField(record, "updated_at"),
		RuntimeKind:       boundedField(record, "runtime_kind", 128),
		RuntimeInstanceID: boundedField(record, "runtime_instance_id", 128),
		AdapterKind:       boundedField(record, "adapter_kind", 128),
		AdapterVersion:    boundedField(record, "adapter_version", 128),
		AgentProvider:     boundedField(record, "agent_provider", 128),
		Agent:             boundedField(record, "agent", 128),
		ConversationID:    safeIDField(record, "conversation_id"),
		PrincipalID:       boundedField(record, "principal_id", 320),
		Identity:          mapIdentity(record["identity_context_json"]),
		IdentityHash:      hashField(record, "identity_hash"),
		PolicyVersion:     boundedField(record, "policy_version", 128),
		PolicyHash:        hashField(record, "policy_hash"),
		CWD:               boundedField(record, "cwd", 4096),
		ExternalID:        safeIDField(record, "external_id"),
		ClosedAt:          stringField(record, "closed_at"),
	}
	if !safeIDPattern.MatchString(session.ID) {
		return SessionRecord{}, fmt.Errorf("id is not a SafeId")
	}
	if !sessionSources[session.Source] {
		// Historical rows can predate the source column default.
		session.Source = "daemon_observed"
	}
	if mode := stringField(record, "mode"); sessionModes[mode] {
		session.Mode = mode
	}
	if err := requireTimestamp("created_at", session.CreatedAt); err != nil {
		return SessionRecord{}, err
	}
	if err := requireTimestamp("updated_at", session.UpdatedAt); err != nil {
		return SessionRecord{}, err
	}
	// Lifecycle coherence: closed requires closed_at, open forbids it, and
	// timestamps never contradict the row's own update stamp.
	switch session.Status {
	case "closed":
		if !timestampPattern.MatchString(session.ClosedAt) {
			session.ClosedAt = session.UpdatedAt
		}
	default:
		session.Status = "open"
		session.ClosedAt = ""
	}
	if compareTimestamps(session.CreatedAt, session.UpdatedAt) > 0 {
		session.CreatedAt = session.UpdatedAt
	}
	if session.ClosedAt != "" && compareTimestamps(session.ClosedAt, session.UpdatedAt) > 0 {
		session.ClosedAt = session.UpdatedAt
	}
	return session, nil
}

// mapAction returns nil for session lifecycle rows: they stay local, and
// the clean contract carries session state via session records instead.
func mapAction(record map[string]any) (*ActionRecord, error) {
	eventType := stringField(record, "canonical_event_type")
	if eventType == eventSessionStart || eventType == eventSessionEnd {
		return nil, nil
	}
	if !actionEventTypes[eventType] {
		return nil, fmt.Errorf("event type %q is outside the clean v1 vocabulary", eventType)
	}

	action := ActionRecord{
		ID:               stringField(record, "id"),
		SessionID:        stringField(record, "session_id"),
		EventType:        eventType,
		Status:           stringField(record, "status"),
		CreatedAt:        stringField(record, "created_at"),
		UpdatedAt:        stringField(record, "updated_at"),
		ToolCallID:       safeIDField(record, "tool_use_id"),
		AdapterEventName: boundedField(record, "adapter_event_name", 128),
		CorrelationKey:   safeIDField(record, "correlation_key"),
		ToolName:         boundedField(record, "tool_name", 128),
		Provider:         boundedField(record, "provider", 128),
		Operation:        boundedField(record, "operation", 128),
		OperationClass:   boundedField(record, "operation_class", 128),
		ResourceClass:    boundedField(record, "resource_class", 128),
		ResourceID:       boundedField(record, "resource_id", 4096),
		Parameters:       objectField(record, "parameters_redacted_json"),
		ParametersHash:   hashField(record, "parameters_hash"),
		Identity:         mapIdentity(record["identity_context_json"]),
		IdentityHash:     hashField(record, "identity_hash"),
		Context:          mapContext(record["context_json"]),
		ContextHash:      hashField(record, "context_hash"),
		PolicyID:         boundedField(record, "policy_id", 128),
		PolicyVersion:    boundedField(record, "policy_version", 128),
		PolicyHash:       hashField(record, "policy_hash"),
		AdapterDecision:  boundedField(record, "adapter_decision", 128),
		ReasonCode:       boundedField(record, "reason_code", 128),
		Reason:           summaryField(record, "reason"),
		ModelVersion:     boundedField(record, "model_version", 128),
		RiskScore:        unitIntervalField(record, "risk_score"),
		RiskThreshold:    unitIntervalField(record, "risk_threshold"),
		Confidence:       unitIntervalField(record, "confidence"),
		MatchedRules:     stringListField(record, "matched_rules_json"),
		RiskSignals:      stringListField(record, "risk_signals_json"),
		OutputSummary:    summaryField(record, "output_summary"),
		OutputHash:       hashField(record, "output_hash"),
		ErrorRedacted:    summaryField(record, "error_redacted"),
		ToolInput:        record["tool_input_captured_json"],
		ToolOutput:       record["tool_output_captured_json"],
		ProposedAt:       timestampField(record, "proposed_at"),
		CompletedAt:      timestampField(record, "completed_at"),
	}
	if category := stringField(record, "decision_category"); decisionCategories[category] {
		action.DecisionCategory = category
	}
	if level := stringField(record, "risk_level"); riskLevels[level] {
		action.RiskLevel = level
	}
	if outcome := stringField(record, "outcome"); actionOutcomes[outcome] {
		action.Outcome = outcome
	}
	if err := requireTimestamp("created_at", action.CreatedAt); err != nil {
		return nil, err
	}
	if err := requireTimestamp("updated_at", action.UpdatedAt); err != nil {
		return nil, err
	}
	if compareTimestamps(action.CreatedAt, action.UpdatedAt) > 0 {
		action.CreatedAt = action.UpdatedAt
	}

	if eventType == "request.decided" {
		if err := applyDecidedMirrors(&action, record); err != nil {
			return nil, err
		}
	}
	if err := requireLifecycleFields(&action); err != nil {
		return nil, err
	}
	return &action, nil
}

// applyDecidedMirrors derives every decision mirror from the fact itself,
// so the mirrors the server cross-checks (tool_call_id, decided_at,
// decision_result, status) cannot disagree with it.
func applyDecidedMirrors(action *ActionRecord, record map[string]any) error {
	factValue := record["decision_fact_json"]
	if factValue == nil {
		return fmt.Errorf("request.decided row carries no decision fact")
	}
	factJSON, err := json.Marshal(factValue)
	if err != nil {
		return fmt.Errorf("encode decision fact: %w", err)
	}
	var fact struct {
		ToolCallID      string `json:"tool_call_id"`
		DecidedAt       string `json:"decided_at"`
		ExecutionAction string `json:"execution_action"`
	}
	if err := json.Unmarshal(factJSON, &fact); err != nil {
		return fmt.Errorf("decode decision fact: %w", err)
	}
	if fact.ToolCallID == "" || fact.DecidedAt == "" {
		return fmt.Errorf("decision fact is missing correlation fields")
	}
	action.DecisionFact = json.RawMessage(factJSON)
	action.ToolCallID = fact.ToolCallID
	action.DecidedAt = fact.DecidedAt
	switch fact.ExecutionAction {
	case "allow":
		action.DecisionResult = "allow"
		action.Status = "authorized"
	case "deny":
		action.DecisionResult = "deny"
		action.Status = "blocked"
	default:
		return fmt.Errorf("decision fact execution action %q", fact.ExecutionAction)
	}
	return nil
}

func requireLifecycleFields(action *ActionRecord) error {
	switch action.EventType {
	case "request.proposed":
		action.Status = "proposed"
		if action.ProposedAt == "" {
			action.ProposedAt = action.CreatedAt
		}
	case "request.decided":
		if action.DecidedAt == "" {
			return fmt.Errorf("request.decided requires decided_at")
		}
	case "request.observed":
		action.Status = "completed"
		action.Outcome = "success"
		if action.CompletedAt == "" {
			action.CompletedAt = action.UpdatedAt
		}
	case "request.failed":
		action.Status = "failed"
		action.Outcome = "error"
		if action.ErrorRedacted == "" {
			action.ErrorRedacted = "tool call failed"
		}
		if action.CompletedAt == "" {
			action.CompletedAt = action.UpdatedAt
		}
	}
	return nil
}

func mapReceipt(record map[string]any) (ReceiptRecord, error) {
	receipt := ReceiptRecord{
		ID:          stringField(record, "id"),
		ActionID:    stringField(record, "action_id"),
		SessionID:   stringField(record, "session_id"),
		ReceiptType: stringField(record, "receipt_type"),
		Payload:     record["receipt_payload_json"],
		Proof: ReceiptProof{
			ReceiptHash: stringField(record, "receipt_hash"),
		},
		CreatedAt: stringField(record, "created_at"),
	}
	if receipt.Payload == nil {
		return ReceiptRecord{}, fmt.Errorf("receipt has no payload")
	}
	if !hashPattern.MatchString(receipt.Proof.ReceiptHash) {
		return ReceiptRecord{}, fmt.Errorf("receipt hash %q is not a sha256 hash", receipt.Proof.ReceiptHash)
	}
	if err := requireTimestamp("created_at", receipt.CreatedAt); err != nil {
		return ReceiptRecord{}, err
	}
	// Unsigned receipts omit the signature entirely; the legacy
	// empty-string/"none" encoding never crosses this wire.
	if stringField(record, "signature_algorithm") == "ed25519" {
		signature := stringField(record, "signature")
		keyID := stringField(record, "key_id")
		if signature != "" && keyID != "" {
			receipt.Proof.Signature = &ReceiptSignature{
				Algorithm: "ed25519",
				KeyID:     keyID,
				Value:     signature,
			}
		}
	}
	return receipt, nil
}

func mapIdentity(value any) *Identity {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	identity := Identity{
		Agent:         boundedString(object["agent"], 128),
		AgentProvider: boundedString(object["agent_provider"], 128),
	}
	if identity == (Identity{}) {
		return nil
	}
	return &identity
}

func mapContext(value any) *ActionContext {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	context := ActionContext{
		CWD:           boundedString(object["cwd"], 4096),
		HookEventName: boundedString(object["hook_event_name"], 128),
	}
	// Locally the capture setting is a configuration object; the wire
	// carries only the effective mode.
	if capture, ok := object["payload_capture"].(map[string]any); ok {
		if mode := boundedString(capture["effective_mode"], 128); captureModes[mode] {
			context.PayloadCapture = mode
		}
	} else if mode := boundedString(object["payload_capture"], 128); captureModes[mode] {
		context.PayloadCapture = mode
	}
	if github, ok := object["github"].(map[string]any); ok {
		if branch := boundedString(github["branch_or_ref"], 512); branch != "" {
			context.GitHub = &ContextGitHub{BranchOrRef: branch}
		}
	}
	if context == (ActionContext{}) {
		return nil
	}
	return &context
}

// --- field helpers -----------------------------------------------------------

func stringField(record map[string]any, key string) string {
	value, _ := record[key].(string)
	return value
}

func boundedField(record map[string]any, key string, max int) string {
	return boundedString(record[key], max)
}

func boundedString(value any, max int) string {
	text, _ := value.(string)
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if len(text) > max {
		return truncateUTF8(text, max)
	}
	return text
}

func summaryField(record map[string]any, key string) string {
	return boundedField(record, key, 4096)
}

func safeIDField(record map[string]any, key string) string {
	value := stringField(record, key)
	if !safeIDPattern.MatchString(value) {
		return ""
	}
	return value
}

func hashField(record map[string]any, key string) string {
	value := stringField(record, key)
	if !hashPattern.MatchString(value) {
		return ""
	}
	return value
}

func timestampField(record map[string]any, key string) string {
	value := stringField(record, key)
	if !timestampPattern.MatchString(value) {
		return ""
	}
	return value
}

func requireTimestamp(field, value string) error {
	if !timestampPattern.MatchString(value) {
		return fmt.Errorf("%s %q is not a UTC RFC 3339 timestamp", field, value)
	}
	return nil
}

func unitIntervalField(record map[string]any, key string) *float64 {
	value, ok := record[key].(float64)
	if !ok || value < 0 || value > 1 {
		return nil
	}
	return &value
}

func objectField(record map[string]any, key string) map[string]any {
	object, ok := record[key].(map[string]any)
	if !ok || len(object) == 0 {
		return nil
	}
	return object
}

func stringListField(record map[string]any, key string) []string {
	values, ok := record[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		text := boundedString(value, 256)
		if text == "" {
			continue
		}
		out = append(out, text)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// compareTimestamps orders two contract timestamps. Lexicographic
// comparison is only correct at equal fractional length, so compare on the
// zero-padded nine-digit form.
func compareTimestamps(a, b string) int {
	return strings.Compare(padTimestamp(a), padTimestamp(b))
}

func padTimestamp(value string) string {
	trimmed := strings.TrimSuffix(value, "Z")
	whole, fraction, _ := strings.Cut(trimmed, ".")
	return whole + "." + fraction + strings.Repeat("0", 9-len(fraction))
}

func truncateUTF8(text string, max int) string {
	for max > 0 && max < len(text) {
		if text[max]&0xC0 != 0x80 {
			return text[:max]
		}
		max--
	}
	return text
}

func stringSet(values ...string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

// Closed-vocabulary guards shared with the store's receipt builder, so the
// payloads it commits to hashes only ever contain contract values.

func ValidRiskLevel(value string) bool { return riskLevels[value] }

func ValidDecisionCategory(value string) bool { return decisionCategories[value] }

func ValidActionOutcome(value string) bool { return actionOutcomes[value] }

func ValidHash(value string) bool { return hashPattern.MatchString(value) }
