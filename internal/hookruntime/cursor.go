package hookruntime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/kontext-security/kontext/internal/hook"
)

const cursorSessionPrefix = "cursor-"

type cursorHookInput struct {
	ConversationID string          `json:"conversation_id"`
	SessionID      string          `json:"session_id"`
	HookEventName  string          `json:"hook_event_name"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolOutput     string          `json:"tool_output"`
	ResultJSON     string          `json:"result_json"`
	ToolUseID      string          `json:"tool_use_id"`
	MCPServerName  string          `json:"mcp_server_name"`
	CWD            string          `json:"cwd"`
	WorkspaceRoots []string        `json:"workspace_roots"`
	TranscriptPath *string         `json:"transcript_path"`
	Prompt         *string         `json:"prompt"`
	ErrorMessage   string          `json:"error_message"`
	IsInterrupt    *bool           `json:"is_interrupt"`
	Duration       *float64        `json:"duration"`
	DurationMs     *float64        `json:"duration_ms"`
}

type cursorHookOutput struct {
	Permission   string `json:"permission,omitempty"`
	UserMessage  string `json:"user_message,omitempty"`
	AgentMessage string `json:"agent_message,omitempty"`
}

// cursorHookNames maps the Cursor events Kontext registers to its own. MCP
// calls are decided and recorded on before/afterMCPExecution, the only events
// that name the server; Cursor's preToolUse/postToolUse copies ("MCP:<tool>")
// are skipped so a call is never decided twice.
var cursorHookNames = map[string]hook.HookName{
	"sessionStart":       hook.HookSessionStart,
	"sessionEnd":         hook.HookSessionEnd,
	"beforeSubmitPrompt": hook.HookUserPromptSubmit,
	"preToolUse":         hook.HookPreToolUse,
	"beforeMCPExecution": hook.HookPreToolUse,
	"postToolUse":        hook.HookPostToolUse,
	"afterMCPExecution":  hook.HookPostToolUse,
	"postToolUseFailure": hook.HookPostToolUseFailed,
	"stop":               hook.HookStop,
}

func DecodeCursorEvent(input []byte, agentName string) (hook.Event, error) {
	var h cursorHookInput
	if err := decodeUseNumber(input, &h); err != nil {
		return hook.Event{}, fmt.Errorf("cursor: decode hook input: %w", err)
	}
	hookName, ok := cursorHookNames[h.HookEventName]
	if !ok {
		return hook.Event{}, fmt.Errorf("cursor: unsupported hook event %q", h.HookEventName)
	}
	sessionID := firstString(h.ConversationID, h.SessionID)
	if sessionID == "" {
		return hook.Event{}, fmt.Errorf("cursor: %s carries no conversation id", h.HookEventName)
	}
	toolName := h.ToolName
	switch h.HookEventName {
	case "beforeMCPExecution", "afterMCPExecution":
		if h.MCPServerName == "" || toolName == "" {
			return hook.Event{}, fmt.Errorf("cursor: %s names no MCP server or tool", h.HookEventName)
		}
		toolName = "mcp__" + cursorToolNamePart(h.MCPServerName) + "__" + cursorToolNamePart(toolName)
	case "preToolUse", "postToolUse", "postToolUseFailure":
		if strings.HasPrefix(toolName, "MCP:") {
			return hook.Event{}, fmt.Errorf("cursor: %s for %s is decided on the MCP events", h.HookEventName, toolName)
		}
	}

	toolInput := cursorToolInput(h.ToolInput)
	if hookName == hook.HookUserPromptSubmit && h.Prompt != nil {
		toolInput["prompt"] = *h.Prompt
	}
	cwd := h.CWD
	if cwd == "" && len(h.WorkspaceRoots) > 0 {
		// The CLI sends an empty cwd for shell calls; the first workspace
		// root is where the agent runs.
		cwd = h.WorkspaceRoots[0]
	}
	output := h.ToolOutput
	if h.HookEventName == "afterMCPExecution" {
		output = h.ResultJSON
	}
	var response map[string]any
	if output != "" {
		response = normalizeToolResponse(json.RawMessage(output))
		if response == nil {
			response = map[string]any{"content": output}
		}
	}
	return hook.Event{
		SessionID:      cursorSessionPrefix + strings.TrimPrefix(sessionID, cursorSessionPrefix),
		Agent:          agentName,
		HookName:       hookName,
		ToolName:       toolName,
		ToolInput:      toolInput,
		ToolResponse:   response,
		ToolUseID:      h.ToolUseID,
		CWD:            cwd,
		TranscriptPath: stringPtrValue(h.TranscriptPath),
		DurationMs:     cursorMillis(h.Duration, h.DurationMs),
		Error:          h.ErrorMessage,
		IsInterrupt:    h.IsInterrupt,
	}, nil
}

// cursorToolInput accepts tool_input as Cursor sends it: an object for
// built-in tools, a JSON-encoded string for MCP calls. Policy evaluation needs
// an object either way.
func cursorToolInput(raw json.RawMessage) map[string]any {
	trimmed := bytes.TrimSpace(raw)
	var text string
	if len(trimmed) > 0 && trimmed[0] == '"' && json.Unmarshal(trimmed, &text) == nil {
		trimmed = bytes.TrimSpace([]byte(text))
	}
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return map[string]any{}
	}
	var obj map[string]any
	if decodeUseNumber(trimmed, &obj) == nil && obj != nil {
		return obj
	}
	var value any
	if decodeUseNumber(trimmed, &value) == nil {
		return map[string]any{"value": value}
	}
	return map[string]any{"raw": string(trimmed)}
}

// cursorToolNamePart spells a server or tool name the way Claude Code and
// Codex do in mcp__ tool names, so MCP config lookups and tool catalogs match.
func cursorToolNamePart(name string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
			return r
		}
		return '_'
	}, name)
}

func cursorMillis(values ...*float64) *int64 {
	for _, value := range values {
		if value != nil && *value >= 0 && *value < math.MaxInt64 {
			ms := int64(*value)
			return &ms
		}
	}
	return nil
}

// EncodeCursorResult only ever denies. An explicit allow would skip Cursor's
// own approval prompt, so allows, fail-opens and every non-blocking event say
// nothing ("{}" is Cursor's no-decision answer). Unknown decisions block.
func EncodeCursorResult(hookName hook.HookName, result hook.Result) ([]byte, error) {
	if hookName != hook.HookPreToolUse || result.FailedOpen || result.Decision == hook.DecisionAllow {
		return []byte("{}"), nil
	}
	reason := result.ClaudeReason()
	return json.Marshal(cursorHookOutput{Permission: string(hook.DecisionDeny), UserMessage: reason, AgentMessage: reason})
}
