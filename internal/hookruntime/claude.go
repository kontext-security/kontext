package hookruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

type claudeHookInput struct {
	SessionID        string          `json:"session_id"`
	SessionIDAlt     string          `json:"sessionId"`
	HookEventName    string          `json:"hook_event_name"`
	HookEventNameAlt string          `json:"hookEventName"`
	HookEventLegacy  string          `json:"hook_event"`
	ToolName         string          `json:"tool_name"`
	ToolNameAlt      string          `json:"toolName"`
	ToolInput        map[string]any  `json:"tool_input"`
	ToolInputAlt     map[string]any  `json:"toolInput"`
	ToolResponse     json.RawMessage `json:"tool_response"`
	ToolResponseAlt  json.RawMessage `json:"toolResponse"`
	ToolUseID        string          `json:"tool_use_id"`
	ToolUseIDAlt     string          `json:"toolUseId"`
	ToolUseIDUpper   string          `json:"toolUseID"`
	Prompt           *string         `json:"prompt"`
	CWD              string          `json:"cwd"`
	PermissionMode   *string         `json:"permission_mode"`
	DurationMs       *int64          `json:"duration_ms"`
	Error            *string         `json:"error"`
	IsInterrupt      *bool           `json:"is_interrupt"`
}

type claudeHookOutput struct {
	HookSpecificOutput *claudeHookSpecificOutput `json:"hookSpecificOutput,omitempty"`
	SuppressOutput     bool                      `json:"suppressOutput,omitempty"`
}

type claudeHookSpecificOutput struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string         `json:"additionalContext,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
}

func DecodeClaudeEvent(input []byte, agentName string) (hook.Event, error) {
	var h claudeHookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return hook.Event{}, fmt.Errorf("claude: decode hook input: %w", err)
	}
	hookName := firstString(h.HookEventName, h.HookEventNameAlt, h.HookEventLegacy)
	if hookName == "" {
		return hook.Event{}, fmt.Errorf("claude: hook event name missing")
	}
	return hook.Event{
		SessionID:      firstString(h.SessionID, h.SessionIDAlt),
		Agent:          agentName,
		HookName:       hook.HookName(hookName),
		ToolName:       firstString(h.ToolName, h.ToolNameAlt),
		ToolInput:      normalizeClaudeToolInput(hookName, h),
		ToolResponse:   normalizeToolResponse(h.ToolResponse, h.ToolResponseAlt),
		ToolUseID:      firstString(h.ToolUseID, h.ToolUseIDAlt, h.ToolUseIDUpper),
		CWD:            h.CWD,
		PermissionMode: stringPtrValue(h.PermissionMode),
		DurationMs:     h.DurationMs,
		Error:          stringPtrValue(h.Error),
		IsInterrupt:    h.IsInterrupt,
	}, nil
}

// normalizeClaudeToolInput carries the UserPromptSubmit payload's top-level
// prompt into tool input, where the rest of the pipeline reads it (same shape
// the Codex adapter produces).
func normalizeClaudeToolInput(hookName string, h claudeHookInput) map[string]any {
	toolInput := firstMap(h.ToolInput, h.ToolInputAlt)
	if hookName != hook.HookUserPromptSubmit.String() || h.Prompt == nil {
		return toolInput
	}
	if toolInput == nil {
		toolInput = map[string]any{}
	}
	if _, exists := toolInput["prompt"]; !exists {
		toolInput["prompt"] = *h.Prompt
	}
	return toolInput
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstMap(values ...map[string]any) map[string]any {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

// normalizeToolResponse decodes the tool_response payload, which Claude Code
// delivers as a JSON object for built-in tools but as an array (of content
// blocks) for MCP tools. Object payloads are returned as-is; any other shape is
// wrapped under "content" so the rest of the pipeline keeps a map[string]any.
func normalizeToolResponse(values ...json.RawMessage) map[string]any {
	for _, raw := range values {
		trimmed := bytes.TrimSpace(raw)
		if len(trimmed) == 0 || string(trimmed) == "null" {
			continue
		}
		var obj map[string]any
		if err := decodeUseNumber(trimmed, &obj); err == nil {
			return obj
		}
		var v any
		if err := decodeUseNumber(trimmed, &v); err == nil {
			return map[string]any{"content": v}
		}
	}
	return nil
}

// decodeUseNumber unmarshals JSON while preserving numeric precision, so large
// integer IDs beyond float64's exact range survive recording and hashing.
func decodeUseNumber(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode(dst)
}

func EncodeClaudeResult(hookEventName string, result hook.Result) ([]byte, error) {
	if hook.HookName(hookEventName) != hook.HookPreToolUse {
		return json.Marshal(claudeHookOutput{SuppressOutput: true})
	}

	permissionDecision := string(result.Decision)
	if permissionDecision != string(hook.DecisionAllow) &&
		permissionDecision != string(hook.DecisionDeny) {
		permissionDecision = string(hook.DecisionDeny)
	}
	reason := result.ClaudeReason()
	if permissionDecision == "allow" && strings.EqualFold(strings.TrimSpace(reason), "allowed") {
		reason = ""
	}
	out := claudeHookOutput{
		HookSpecificOutput: &claudeHookSpecificOutput{
			HookEventName:            hookEventName,
			PermissionDecision:       permissionDecision,
			PermissionDecisionReason: reason,
			UpdatedInput:             result.UpdatedInput,
		},
		SuppressOutput: result.UpdatedInput != nil,
	}
	return json.Marshal(out)
}

func stringPtrValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
