package hookruntime

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/kontext-security/kontext/internal/antigravitytools"
	"github.com/kontext-security/kontext/internal/hook"
)

const antigravitySessionPrefix = "antigravity-"

// antigravityHookInput is one hook payload. Payloads name neither their event
// nor their call: the hook command says which event ran, and a call is the
// conversation's step number, which its pre and post events share.
type antigravityHookInput struct {
	ConversationID string   `json:"conversationId"`
	WorkspacePaths []string `json:"workspacePaths"`
	TranscriptPath string   `json:"transcriptPath"`
	ModelName      string   `json:"modelName"`
	LastUserInput  string   `json:"lastUserInput"`
	ToolCall       *struct {
		Name string         `json:"name"`
		Args map[string]any `json:"args"`
	} `json:"toolCall"`
	StepIdx       *int64 `json:"stepIdx"`
	Error         string `json:"error"`
	InvocationNum *int64 `json:"invocationNum"`
}

type antigravityPreToolOutput struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// antigravityNoDecision is the only neutral PreToolUse answer that is also
// documented: measured on 2.29.0, it keeps the person's approval prompt, while
// "{}" and an empty decision deny the call and auto_approve skips the prompt.
// Every other event accepts it too, so a failure before the event is known can
// print it.
const antigravityNoDecision = `{"decision":"allow"}`

// AntigravityNoDecision is what a hook prints when Kontext has no decision.
func AntigravityNoDecision() []byte { return []byte(antigravityNoDecision) }

// AntigravityToolUseID names a call by its conversation and step, the identity
// its hook events and its transcript row have in common.
func AntigravityToolUseID(conversationID string, step int64) string {
	return fmt.Sprintf("agy-%s-%d", conversationID, step)
}

// DecodeAntigravityEvent reads the payload of the event named by the hook
// command. Kontext runs PreInvocation under user-prompt-submit: the app has no
// prompt event, and the first model call of a run carries the person's input.
// A resumed run (a sub-agent reporting back) repeats that input and mints a
// second turn with it; the hook keeps no state to tell the two apart.
func DecodeAntigravityEvent(input []byte, agentName string, hookName hook.HookName) (hook.Event, error) {
	var h antigravityHookInput
	if err := decodeUseNumber(input, &h); err != nil {
		return hook.Event{}, fmt.Errorf("antigravity: decode hook input: %w", err)
	}
	if h.ConversationID == "" {
		return hook.Event{}, fmt.Errorf("antigravity: %s carries no conversation id", hookName)
	}
	event := hook.Event{
		SessionID:      antigravitySessionPrefix + strings.TrimPrefix(h.ConversationID, antigravitySessionPrefix),
		Agent:          agentName,
		HookName:       hookName,
		TranscriptPath: h.TranscriptPath,
		Model:          h.ModelName,
	}
	if len(h.WorkspacePaths) > 0 {
		event.CWD = h.WorkspacePaths[0]
	}
	switch hookName {
	case hook.HookSessionStart, hook.HookStop:
	case hook.HookUserPromptSubmit:
		if h.InvocationNum != nil && *h.InvocationNum != 0 {
			return hook.Event{}, fmt.Errorf("antigravity: model call %d continues a turn", *h.InvocationNum)
		}
		if h.LastUserInput == "" {
			return hook.Event{}, fmt.Errorf("antigravity: model call names no prompt")
		}
		event.ToolInput = map[string]any{"prompt": h.LastUserInput}
	case hook.HookPreToolUse, hook.HookPostToolUse:
		if h.ToolCall == nil || h.ToolCall.Name == "" {
			return hook.Event{}, fmt.Errorf("antigravity: %s carries no tool call", hookName)
		}
		name, toolInput, ok := antigravitytools.Call(h.ToolCall.Name, h.ToolCall.Args)
		if !ok {
			return hook.Event{}, fmt.Errorf("antigravity: %s names no MCP server or tool", h.ToolCall.Name)
		}
		event.ToolName, event.ToolInput = name, toolInput
		event.UserRequest = h.LastUserInput
		if h.StepIdx != nil {
			event.ToolUseID = AntigravityToolUseID(strings.TrimPrefix(h.ConversationID, antigravitySessionPrefix), *h.StepIdx)
		}
		// Only a shell call runs where its arguments say. Any other tool's arguments
		// are its own data, and the MCP config lookup reads this directory, so a
		// call must not be able to pick the workspace whose config identifies it.
		if cwd, _ := toolInput["cwd"].(string); cwd != "" && name == "Bash" {
			event.CWD = cwd
		}
		// A command that exits non-zero still reports no error: the app calls
		// that a completed step. Only a step that could not run sets it.
		if hookName == hook.HookPostToolUse && h.Error != "" {
			event.HookName, event.Error = hook.HookPostToolUseFailed, h.Error
		}
	default:
		return hook.Event{}, fmt.Errorf("antigravity: unsupported hook event %q", hookName)
	}
	return event, nil
}

// EncodeAntigravityResult answers only PreToolUse with a decision. Unknown
// decisions block, as for every agent.
func EncodeAntigravityResult(hookName hook.HookName, result hook.Result) ([]byte, error) {
	if hookName != hook.HookPreToolUse {
		return []byte("{}"), nil
	}
	if result.FailedOpen || result.Decision == hook.DecisionAllow {
		return AntigravityNoDecision(), nil
	}
	return json.Marshal(antigravityPreToolOutput{Decision: string(hook.DecisionDeny), Reason: result.ClaudeReason()})
}
