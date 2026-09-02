package cedareval

import (
	"fmt"
	"unicode/utf8"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

const (
	RequestContractVersionV2 = 2
	EndpointEntityTypeV2     = "Kontext::Endpoint"
	AgentEntityTypeV2        = "Kontext::Agent"
	ToolEntityTypeV2         = "Kontext::Tool"
	AgentClaudeCodeV2        = "anthropic-claude-code"
	AgentCodexV2             = "openai-codex"
	ToolShellV2              = "shell"
	ToolUnknownV2            = "unknown"
)

type ShellProjectionV2 struct {
	Version       int      `json:"version"`
	Program       string   `json:"program"`
	Facts         []string `json:"facts"`
	Features      []string `json:"features"`
	ParseComplete bool     `json:"parseComplete"`
}

type ToolUseInputV2 struct {
	Version    int                `json:"version"`
	EndpointID string             `json:"endpointId"`
	AgentID    string             `json:"agentId"`
	SessionID  string             `json:"sessionId"`
	ToolID     string             `json:"toolId"`
	ToolInput  map[string]any     `json:"toolInput"`
	Shell      *ShellProjectionV2 `json:"shell,omitempty"`
}

func BuildRequestV2(input ToolUseInputV2) (cedar.Request, cedar.EntityMap, error) {
	if err := validateInputV2(input); err != nil {
		return cedar.Request{}, nil, newConversionError("invalid_v2_request", "", err.Error())
	}
	inputJSON, err := payloadcapture.CanonicalJSON(input.ToolInput)
	if err != nil {
		return cedar.Request{}, nil, newConversionError("invalid_json_value", "", fmt.Sprintf("cedareval: canonical tool input: %v", err))
	}

	context := cedar.RecordMap{
		cedar.String("agent"): cedar.NewEntityUID(
			cedar.EntityType(AgentEntityTypeV2),
			cedar.String(input.AgentID),
		),
		cedar.String("inputJson"): cedar.String(inputJSON),
		cedar.String("session"): cedar.NewRecord(cedar.RecordMap{
			cedar.String("id"): cedar.String(input.SessionID),
		}),
	}
	if input.Shell != nil {
		context[cedar.String("shell")] = shellRecord(*input.Shell)
	}

	principal := cedar.NewEntityUID(
		cedar.EntityType(EndpointEntityTypeV2),
		cedar.String(input.EndpointID),
	)
	agent := cedar.NewEntityUID(
		cedar.EntityType(AgentEntityTypeV2),
		cedar.String(input.AgentID),
	)
	resource := cedar.NewEntityUID(
		cedar.EntityType(ToolEntityTypeV2),
		cedar.String(input.ToolID),
	)
	request := cedar.Request{
		Principal: principal,
		Action: cedar.NewEntityUID(
			cedar.EntityType(ActionEntityType),
			cedar.String(ToolUseActionID),
		),
		Resource: resource,
		Context:  cedar.NewRecord(context),
	}
	empty := cedar.NewRecord(cedar.RecordMap{})
	entities := cedar.EntityMap{}
	for _, uid := range []cedar.EntityUID{principal, agent, resource} {
		entities[uid] = cedar.Entity{
			UID:        uid,
			Parents:    cedar.NewEntityUIDSet(),
			Attributes: empty,
			Tags:       empty,
		}
	}
	return request, entities, nil
}

func (e *Evaluator) EvaluateV2(input ToolUseInputV2) (Result, error) {
	request, entities, err := BuildRequestV2(input)
	if err != nil {
		return Result{}, err
	}
	return e.evaluateRequestWithEntities(request, entities, nil)
}

func shellRecord(shell ShellProjectionV2) cedar.Record {
	facts := make([]cedar.Value, 0, len(shell.Facts))
	for _, fact := range shell.Facts {
		facts = append(facts, cedar.String(fact))
	}
	features := make([]cedar.Value, 0, len(shell.Features))
	for _, feature := range shell.Features {
		features = append(features, cedar.String(feature))
	}
	return cedar.NewRecord(cedar.RecordMap{
		cedar.String("version"):       cedar.Long(shell.Version),
		cedar.String("program"):       cedar.String(shell.Program),
		cedar.String("facts"):         cedar.NewSet(facts...),
		cedar.String("features"):      cedar.NewSet(features...),
		cedar.String("parseComplete"): cedar.Boolean(shell.ParseComplete),
	})
}

func validateInputV2(input ToolUseInputV2) error {
	if input.Version != RequestContractVersionV2 {
		return fmt.Errorf("cedareval: unsupported request contract version %d", input.Version)
	}
	if !validText(input.EndpointID, 1024) {
		return fmt.Errorf("cedareval: endpoint id must contain 1 to 1024 characters")
	}
	if input.AgentID != AgentClaudeCodeV2 && input.AgentID != AgentCodexV2 {
		return fmt.Errorf("cedareval: unsupported agent %q", input.AgentID)
	}
	if !validText(input.SessionID, 1024) {
		return fmt.Errorf("cedareval: session id must contain 1 to 1024 characters")
	}
	if !validText(input.ToolID, 4096) {
		return fmt.Errorf("cedareval: tool id must contain 1 to 4096 characters")
	}
	if input.ToolInput == nil {
		return fmt.Errorf("cedareval: tool input must be a JSON object")
	}
	if (input.ToolID == ToolShellV2) != (input.Shell != nil) {
		return fmt.Errorf("cedareval: shell projection must be present only for the shell tool")
	}
	if input.Shell == nil {
		return nil
	}
	if input.Shell.Version != 1 || !validText(input.Shell.Program, 4096) {
		return fmt.Errorf("cedareval: invalid shell projection")
	}
	if err := validateStrings(input.Shell.Facts); err != nil {
		return fmt.Errorf("cedareval: invalid shell facts: %w", err)
	}
	if err := validateStrings(input.Shell.Features); err != nil {
		return fmt.Errorf("cedareval: invalid shell features: %w", err)
	}
	return nil
}

func validateStrings(values []string) error {
	if len(values) > 1024 {
		return fmt.Errorf("too many values")
	}
	for _, value := range values {
		if !validText(value, 4096) {
			return fmt.Errorf("value must contain 1 to 4096 characters")
		}
	}
	return nil
}

func validText(value string, maximum int) bool {
	return utf8.ValidString(value) && stringLength(value) > 0 && stringLength(value) <= maximum
}
