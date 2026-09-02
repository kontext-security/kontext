package hookruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kontext-security/kontext/internal/hook"
)

const codexSessionPrefix = "codex-"

type codexHookInput struct {
	SessionID      string          `json:"session_id"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	ToolUseID      string          `json:"tool_use_id"`
	CWD            string          `json:"cwd"`
	PermissionMode *string         `json:"permission_mode"`
	Prompt         *string         `json:"prompt"`
	Source         *string         `json:"source"`
}

type codexHookOutput struct {
	Continue           *bool                    `json:"continue,omitempty"`
	StopReason         string                   `json:"stopReason,omitempty"`
	SystemMessage      string                   `json:"systemMessage,omitempty"`
	Decision           string                   `json:"decision,omitempty"`
	Reason             string                   `json:"reason,omitempty"`
	HookSpecificOutput *codexHookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

type codexHookSpecificOutput struct {
	HookEventName            string         `json:"hookEventName"`
	PermissionDecision       string         `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string         `json:"permissionDecisionReason,omitempty"`
	AdditionalContext        string         `json:"additionalContext,omitempty"`
	UpdatedInput             map[string]any `json:"updatedInput,omitempty"`
}

func DecodeCodexEvent(input []byte, agentName string) (hook.Event, error) {
	var h codexHookInput
	if err := json.Unmarshal(input, &h); err != nil {
		return hook.Event{}, fmt.Errorf("codex: decode hook input: %w", err)
	}
	if h.HookEventName == "" {
		return hook.Event{}, fmt.Errorf("codex: hook event name missing")
	}
	hookName := hook.HookName(h.HookEventName)
	if !codexSupportedHook(hookName) {
		return hook.Event{}, fmt.Errorf("codex: unsupported hook event %q", h.HookEventName)
	}

	toolInput, err := normalizeCodexToolInput(h)
	if err != nil {
		return hook.Event{}, err
	}
	return hook.Event{
		SessionID:      codexSessionID(h.SessionID),
		Agent:          agentName,
		HookName:       hookName,
		ToolName:       h.ToolName,
		ToolInput:      toolInput,
		ToolResponse:   normalizeToolResponse(h.ToolResponse),
		ToolUseID:      h.ToolUseID,
		CWD:            h.CWD,
		PermissionMode: stringPtrValue(h.PermissionMode),
	}, nil
}

func EncodeCodexResult(hookEventName string, result hook.Result) ([]byte, error) {
	hookName := hook.HookName(hookEventName)
	if !codexSupportedHook(hookName) {
		return nil, fmt.Errorf("codex: unsupported hook event %q", hookEventName)
	}

	reason := codexMeaningfulReason(result)
	if hookName == hook.HookPreToolUse {
		return encodeCodexPreToolUseResult(hookEventName, result, reason)
	}
	return encodeCodexNonPreToolUseResult(hookEventName, result, reason)
}

func encodeCodexPreToolUseResult(hookEventName string, result hook.Result, reason string) ([]byte, error) {
	if result.Decision != hook.DecisionAllow {
		return json.Marshal(codexHookOutput{
			HookSpecificOutput: &codexHookSpecificOutput{
				HookEventName:            hookEventName,
				PermissionDecision:       string(hook.DecisionDeny),
				PermissionDecisionReason: result.ClaudeReason(),
			},
		})
	}

	if result.UpdatedInput == nil && reason == "" {
		return json.Marshal(codexHookOutput{})
	}
	out := codexHookOutput{
		HookSpecificOutput: &codexHookSpecificOutput{
			HookEventName:     hookEventName,
			AdditionalContext: reason,
			UpdatedInput:      result.UpdatedInput,
		},
	}
	if result.UpdatedInput != nil {
		out.HookSpecificOutput.PermissionDecision = string(hook.DecisionAllow)
	}
	return json.Marshal(out)
}

func encodeCodexNonPreToolUseResult(hookEventName string, result hook.Result, reason string) ([]byte, error) {
	if result.Decision == hook.DecisionDeny {
		switch hook.HookName(hookEventName) {
		case hook.HookPostToolUse, hook.HookUserPromptSubmit:
			return json.Marshal(codexHookOutput{
				Decision: "block",
				Reason:   result.ClaudeReason(),
			})
		case hook.HookSessionStart:
			cont := false
			return json.Marshal(codexHookOutput{
				Continue:   &cont,
				StopReason: result.ClaudeReason(),
			})
		case hook.HookStop:
			return json.Marshal(codexHookOutput{})
		}
	}

	if hook.HookName(hookEventName) == hook.HookStop {
		return json.Marshal(codexHookOutput{})
	}
	if reason == "" {
		return json.Marshal(codexHookOutput{})
	}
	return json.Marshal(codexHookOutput{
		HookSpecificOutput: &codexHookSpecificOutput{
			HookEventName:     hookEventName,
			AdditionalContext: reason,
		},
	})
}

func codexSupportedHook(hookName hook.HookName) bool {
	switch hookName {
	case hook.HookSessionStart,
		hook.HookPreToolUse,
		hook.HookPostToolUse,
		hook.HookUserPromptSubmit,
		hook.HookStop:
		return true
	default:
		return false
	}
}

func codexSessionID(sessionID string) string {
	if sessionID == "" || strings.HasPrefix(sessionID, codexSessionPrefix) {
		return sessionID
	}
	return codexSessionPrefix + sessionID
}

func normalizeCodexToolInput(h codexHookInput) (map[string]any, error) {
	toolInput, err := normalizeCodexJSONMap(h.ToolInput)
	if err != nil {
		return nil, err
	}
	if toolInput == nil {
		// Codex omits tool_input (or sends null) for calls without
		// arguments; policy evaluation needs a JSON object either way.
		toolInput = map[string]any{}
	}
	if h.HookEventName == hook.HookUserPromptSubmit.String() && h.Prompt != nil {
		toolInput["prompt"] = *h.Prompt
	}
	if h.HookEventName == hook.HookSessionStart.String() && h.Source != nil {
		toolInput["source"] = *h.Source
	}
	return toolInput, nil
}

func normalizeCodexJSONMap(raw json.RawMessage) (map[string]any, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}
	var obj map[string]any
	if err := decodeUseNumber(trimmed, &obj); err == nil {
		return obj, nil
	}
	var value any
	if err := decodeUseNumber(trimmed, &value); err != nil {
		return nil, fmt.Errorf("codex: decode JSON value: %w", err)
	}
	return map[string]any{"value": value}, nil
}

func codexMeaningfulReason(result hook.Result) string {
	reason := strings.TrimSpace(result.Reason)
	switch {
	case reason == "":
		return ""
	case strings.EqualFold(reason, "allowed"):
		return ""
	case strings.EqualFold(reason, "telemetry allowed"):
		return ""
	case strings.EqualFold(reason, "async telemetry event recorded"):
		return ""
	case strings.HasPrefix(reason, "Kontext observe mode: would allow;"):
		return ""
	default:
		return reason
	}
}
