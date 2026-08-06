package hook

import "strings"

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

// ReasonOrDefault returns the decision reason, substituting a generic
// user-facing message for denials that carry none. Hook encoders use it so an
// agent never shows an empty block reason.
func (r Result) ReasonOrDefault() string {
	reason := r.Reason
	if reason == "" && r.Decision == DecisionDeny {
		return "Blocked by Kontext access policy."
	}
	return reason
}
