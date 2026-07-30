package hook

import (
	"errors"
	"strings"
)

// ErrSkipEvent reports a hook event an adapter recognizes but deliberately does
// not translate — a lifecycle signal that carries no authorization decision and
// must not be recorded as one.
//
// Adapters wrap it; hook runners test for it with errors.Is and exit
// successfully without writing a decision. It exists because some agent
// runtimes read a non-zero hook exit as "block the tool call", so reporting an
// unhandled event as a decode failure would stall the agent on an event we
// simply chose not to handle.
var ErrSkipEvent = errors.New("hook event skipped by adapter")

type HookName string

const (
	HookSessionStart      HookName = "SessionStart"
	HookPreToolUse        HookName = "PreToolUse"
	HookPostToolUse       HookName = "PostToolUse"
	HookPostToolUseFailed HookName = "PostToolUseFailure"
	HookSessionEnd        HookName = "SessionEnd"
	HookUserPromptSubmit  HookName = "UserPromptSubmit"
	HookStop              HookName = "Stop"
)

func (h HookName) String() string {
	return string(h)
}

func (h HookName) IsKnown() bool {
	switch h {
	case HookSessionStart, HookPreToolUse, HookPostToolUse, HookPostToolUseFailed, HookSessionEnd, HookUserPromptSubmit, HookStop:
		return true
	default:
		return false
	}
}

func (h HookName) CanBlock() bool {
	return h == HookPreToolUse || h == HookUserPromptSubmit
}

type EventAlias struct {
	Name  HookName
	Alias string
}

var eventAliases = []EventAlias{
	{Name: HookSessionStart, Alias: "session-start"},
	{Name: HookPreToolUse, Alias: "pre-tool-use"},
	{Name: HookPostToolUse, Alias: "post-tool-use"},
	{Name: HookPostToolUseFailed, Alias: "post-tool-use-failure"},
	{Name: HookSessionEnd, Alias: "session-end"},
	{Name: HookUserPromptSubmit, Alias: "user-prompt-submit"},
	{Name: HookStop, Alias: "stop"},
}

func ParseEventAlias(value string) (HookName, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	for _, event := range eventAliases {
		if normalized == event.Alias {
			return event.Name, true
		}
	}
	return "", false
}

func AliasForEvent(name HookName) (string, bool) {
	for _, event := range eventAliases {
		if event.Name == name {
			return event.Alias, true
		}
	}
	return "", false
}

type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionDeny  Decision = "deny"
)

func NormalizeDecision(value string) (Decision, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(DecisionAllow):
		return DecisionAllow, true
	case string(DecisionDeny):
		return DecisionDeny, true
	default:
		return "", false
	}
}

type Event struct {
	SessionID      string
	Agent          string
	HookName       HookName
	ToolName       string
	ToolInput      map[string]any
	ToolResponse   map[string]any
	ToolUseID      string
	CWD            string
	PermissionMode string
	DurationMs     *int64
	Error          string
	IsInterrupt    *bool
}

type Result struct {
	Decision     Decision
	Reason       string
	ReasonCode   string
	RequestID    string
	EventID      string
	Mode         string
	Epoch        string
	UpdatedInput map[string]any
	metadata     any
}

func WithMetadata(result Result, metadata any) Result {
	result.metadata = metadata
	return result
}

func (r Result) Metadata() any {
	return r.metadata
}

func (r Result) Allowed() bool {
	return r.Decision == DecisionAllow
}

func (r Result) Blocking() bool {
	return r.Decision == DecisionDeny
}

func (r Result) ClaudeReason() string {
	reason := r.Reason
	if reason == "" && r.Decision == DecisionDeny {
		return "Blocked by Kontext access policy."
	}
	return reason
}
