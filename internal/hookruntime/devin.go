package hookruntime

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

// devinDecisionBlock is the decision verb the Devin runtime understands on a
// pre-tool-use hook's stdout. Devin surfaces the accompanying reason to the
// agent verbatim, so reasons double as policy messaging.
const devinDecisionBlock = "block"

// devinHookInput mirrors the payload the Devin runtime writes to a plugin
// hook's stdin. Devin emits snake_case only, so unlike the Claude Code adapter
// there are no camelCase aliases to tolerate.
//
// Fields Devin sends that we deliberately do not decode:
//
//   - prompt_id: a per-turn correlator with no home on hook.Event yet. It is
//     deliberately NOT folded into ToolInput, because ToolInput becomes the
//     Cedar evaluation context; injecting a synthetic attribute there would
//     make it policy-visible and would change the parameters hash recorded on
//     every decision.
//   - summary: only present on the compaction event, which is skipped outright.
//     It carries verbatim conversation content and must not reach the ledger
//     without going through payload capture.
type devinHookInput struct {
	HookEventName string          `json:"hook_event_name"`
	SessionID     string          `json:"session_id"`
	ToolName      string          `json:"tool_name"`
	ToolInput     json.RawMessage `json:"tool_input"`
	ToolResponse  json.RawMessage `json:"tool_response"`
	ToolUseID     string          `json:"tool_use_id"`
}

// devinHookOutput is the decision object Devin parses from hook stdout. An
// empty object is the "no directive, continue" form.
type devinHookOutput struct {
	Decision string `json:"decision,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// DecodeDevinEvent translates a Devin hook payload into a hook.Event.
//
// Events Devin emits that carry no authorization decision — and any event name
// this adapter does not recognize — are reported as hook.ErrSkipEvent rather
// than as a decode failure. That distinction matters: the Devin runtime treats
// a non-zero hook exit as "block the tool call", so failing on an event we
// simply do not handle would stall the agent on a legitimate lifecycle signal.
//
// A payload that is malformed or missing its event name is still an error. That
// indicates a bug or a contract change rather than an event we chose not to
// handle, and failing closed on it is the safer default.
func DecodeDevinEvent(input []byte, agentName string) (hook.Event, error) {
	var h devinHookInput
	if err := decodeUseNumber(input, &h); err != nil {
		return hook.Event{}, fmt.Errorf("devin: decode hook input: %w", err)
	}
	if h.HookEventName == "" {
		return hook.Event{}, fmt.Errorf("devin: hook event name missing")
	}

	hookName := hook.HookName(h.HookEventName)
	if !devinSupportedHook(hookName) {
		return hook.Event{}, fmt.Errorf("devin: event %s: %w", h.HookEventName, hook.ErrSkipEvent)
	}

	toolInput, err := normalizeDevinToolInput(h.ToolInput)
	if err != nil {
		return hook.Event{}, err
	}
	return hook.Event{
		// Devin session IDs are already namespaced (devin-<uuid>), so unlike
		// the Codex adapter there is no prefix to add and no synthetic ID to
		// mint — session_id and tool_use_id map straight through.
		SessionID:    h.SessionID,
		Agent:        agentName,
		HookName:     hookName,
		ToolName:     h.ToolName,
		ToolInput:    toolInput,
		ToolResponse: normalizeToolResponse(h.ToolResponse),
		ToolUseID:    h.ToolUseID,
	}, nil
}

// EncodeDevinResult renders a decision in the form Devin parses from stdout.
//
// Only pre-tool-use carries a decision; every other event is observation and
// must emit no directive. Anything other than an explicit allow blocks, so an
// unrecognized decision value fails closed rather than letting a tool call
// through.
func EncodeDevinResult(hookEventName string, result hook.Result) ([]byte, error) {
	if hook.HookName(hookEventName) != hook.HookPreToolUse {
		return json.Marshal(devinHookOutput{})
	}

	// Devin applies an updated tool input by REPLACING the original wholesale
	// rather than merging it. Emitting a partial rewrite would silently drop
	// every field the policy did not restate — turning a redaction into an
	// arbitrary change to the agent's command — and the post-tool-use hook
	// would then observe only the rewritten input, so the original would never
	// reach the ledger. Until input rewriting is modelled end to end, refuse
	// visibly instead of rewriting wrongly.
	if result.UpdatedInput != nil {
		return json.Marshal(devinHookOutput{
			Decision: devinDecisionBlock,
			Reason:   "Kontext: policy requested an input rewrite, which this adapter does not support; refusing instead of altering the request.",
		})
	}

	if result.Decision != hook.DecisionAllow {
		return json.Marshal(devinHookOutput{
			Decision: devinDecisionBlock,
			Reason:   result.ClaudeReason(),
		})
	}
	return json.Marshal(devinHookOutput{})
}

// devinSupportedHook reports the Devin events this adapter translates. Devin
// also emits compaction and permission-request events; both are skipped, as is
// any event name added in future, so an unhandled event never blocks a tool
// call.
func devinSupportedHook(hookName hook.HookName) bool {
	switch hookName {
	case hook.HookSessionStart,
		hook.HookPreToolUse,
		hook.HookPostToolUse,
		hook.HookSessionEnd:
		return true
	default:
		return false
	}
}

// normalizeDevinToolInput decodes tool_input into the map the rest of the
// pipeline expects. An absent or null input yields nil. A non-object input is
// not expected from Devin; it is wrapped rather than rejected so an unforeseen
// shape degrades to a recordable event instead of blocking the agent.
func normalizeDevinToolInput(raw json.RawMessage) (map[string]any, error) {
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
		return nil, fmt.Errorf("devin: decode tool input: %w", err)
	}
	return map[string]any{"value": value}, nil
}
