package hookruntime

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestDecodeDevinEventMapsPreToolUsePayload(t *testing.T) {
	t.Parallel()

	input := []byte(`{
		"hook_event_name": "PreToolUse",
		"session_id": "devin-02714895131a4094893ce70889e3f2b6",
		"prompt_id": "prompt-1",
		"tool_name": "exec",
		"tool_use_id": "toolu_9",
		"tool_input": {"command": "curl https://example.com"}
	}`)

	event, err := DecodeDevinEvent(input, "devin")
	if err != nil {
		t.Fatalf("DecodeDevinEvent() error = %v", err)
	}
	if event.HookName != hook.HookPreToolUse {
		t.Fatalf("HookName = %q, want PreToolUse", event.HookName)
	}
	// Devin session IDs arrive already namespaced; the adapter must not add a
	// prefix or mint a replacement.
	if event.SessionID != "devin-02714895131a4094893ce70889e3f2b6" {
		t.Fatalf("SessionID = %q, want the payload value verbatim", event.SessionID)
	}
	if event.ToolName != "exec" {
		t.Fatalf("ToolName = %q, want exec", event.ToolName)
	}
	if event.ToolUseID != "toolu_9" {
		t.Fatalf("ToolUseID = %q, want toolu_9", event.ToolUseID)
	}
	if event.Agent != "devin" {
		t.Fatalf("Agent = %q, want devin", event.Agent)
	}
	if got := event.ToolInput["command"]; got != "curl https://example.com" {
		t.Fatalf("ToolInput[command] = %v, want the command", got)
	}
}

// prompt_id must not leak into ToolInput: ToolInput becomes the Cedar
// evaluation context, so a synthetic attribute there would be policy-visible
// and would change the recorded parameters hash.
func TestDecodeDevinEventKeepsPromptIDOutOfToolInput(t *testing.T) {
	t.Parallel()

	event, err := DecodeDevinEvent([]byte(
		`{"hook_event_name":"PreToolUse","prompt_id":"prompt-1","tool_name":"exec","tool_input":{"command":"ls"}}`,
	), "devin")
	if err != nil {
		t.Fatalf("DecodeDevinEvent() error = %v", err)
	}
	if len(event.ToolInput) != 1 {
		t.Fatalf("ToolInput = %v, want only the original tool input keys", event.ToolInput)
	}
	if _, present := event.ToolInput["prompt_id"]; present {
		t.Fatal("ToolInput contains prompt_id, want it excluded from the Cedar context")
	}
}

func TestDecodeDevinEventCapturesToolResponse(t *testing.T) {
	t.Parallel()

	event, err := DecodeDevinEvent([]byte(
		`{"hook_event_name":"PostToolUse","tool_name":"exec","tool_input":{},"tool_response":{"success":false,"error":"boom"}}`,
	), "devin")
	if err != nil {
		t.Fatalf("DecodeDevinEvent() error = %v", err)
	}
	if event.ToolResponse["success"] != false {
		t.Fatalf("ToolResponse[success] = %v, want false", event.ToolResponse["success"])
	}
	if event.ToolResponse["error"] != "boom" {
		t.Fatalf("ToolResponse[error] = %v, want boom", event.ToolResponse["error"])
	}
}

func TestDecodeDevinEventPreservesLargeIntegerPrecision(t *testing.T) {
	t.Parallel()

	event, err := DecodeDevinEvent([]byte(
		`{"hook_event_name":"PreToolUse","tool_name":"exec","tool_input":{"id":12345678901234567890}}`,
	), "devin")
	if err != nil {
		t.Fatalf("DecodeDevinEvent() error = %v", err)
	}
	number, ok := event.ToolInput["id"].(json.Number)
	if !ok {
		t.Fatalf("ToolInput[id] = %T, want json.Number", event.ToolInput["id"])
	}
	if number.String() != "12345678901234567890" {
		t.Fatalf("ToolInput[id] = %s, want the exact literal", number)
	}
}

// Events Devin emits that carry no decision, and any event name added later,
// must report ErrSkipEvent. Reporting a decode failure would exit non-zero,
// which the Devin runtime reads as "block the tool call".
func TestDecodeDevinEventSkipsEventsWithoutDecisions(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"PostCompaction", "PermissionRequest", "SomeFutureEvent"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := DecodeDevinEvent([]byte(`{"hook_event_name":"`+name+`","session_id":"devin-1"}`), "devin")
			if !errors.Is(err, hook.ErrSkipEvent) {
				t.Fatalf("DecodeDevinEvent() error = %v, want ErrSkipEvent", err)
			}
		})
	}
}

func TestDecodeDevinEventTranslatesSessionLifecycle(t *testing.T) {
	t.Parallel()

	for name, want := range map[string]hook.HookName{
		"SessionStart": hook.HookSessionStart,
		"SessionEnd":   hook.HookSessionEnd,
		"PostToolUse":  hook.HookPostToolUse,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			event, err := DecodeDevinEvent([]byte(`{"hook_event_name":"`+name+`","session_id":"devin-1"}`), "devin")
			if err != nil {
				t.Fatalf("DecodeDevinEvent() error = %v", err)
			}
			if event.HookName != want {
				t.Fatalf("HookName = %q, want %q", event.HookName, want)
			}
		})
	}
}

// A malformed payload is a contract violation rather than an event we chose not
// to handle, so it must stay an error and must not be mistaken for a skip.
func TestDecodeDevinEventRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for name, input := range map[string]string{
		"missing event name": `{"tool_name":"exec"}`,
		"not json":           `{`,
		"trailing value":     `{"hook_event_name":"PreToolUse"} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := DecodeDevinEvent([]byte(input), "devin")
			if err == nil {
				t.Fatal("DecodeDevinEvent() error = nil, want a decode error")
			}
			if errors.Is(err, hook.ErrSkipEvent) {
				t.Fatalf("DecodeDevinEvent() error = %v, want a failure rather than a skip", err)
			}
		})
	}
}

func TestDecodeDevinEventAllowsAbsentToolInput(t *testing.T) {
	t.Parallel()

	event, err := DecodeDevinEvent([]byte(`{"hook_event_name":"SessionStart","tool_input":null}`), "devin")
	if err != nil {
		t.Fatalf("DecodeDevinEvent() error = %v", err)
	}
	if event.ToolInput != nil {
		t.Fatalf("ToolInput = %v, want nil", event.ToolInput)
	}
}

func TestEncodeDevinResultBlocksPreToolUseDeny(t *testing.T) {
	t.Parallel()

	out, err := EncodeDevinResult(hook.HookPreToolUse.String(), hook.Result{
		Decision: hook.DecisionDeny,
		Reason:   "network egress is not permitted",
	})
	if err != nil {
		t.Fatalf("EncodeDevinResult() error = %v", err)
	}
	var decoded devinHookOutput
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", out, err)
	}
	if decoded.Decision != "block" {
		t.Fatalf("Decision = %q, want block", decoded.Decision)
	}
	// Devin surfaces this string to the agent verbatim, so it must survive.
	if decoded.Reason != "network egress is not permitted" {
		t.Fatalf("Reason = %q, want the policy reason verbatim", decoded.Reason)
	}
}

func TestEncodeDevinResultAlwaysCarriesABlockReason(t *testing.T) {
	t.Parallel()

	out, err := EncodeDevinResult(hook.HookPreToolUse.String(), hook.Result{Decision: hook.DecisionDeny})
	if err != nil {
		t.Fatalf("EncodeDevinResult() error = %v", err)
	}
	var decoded devinHookOutput
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", out, err)
	}
	if strings.TrimSpace(decoded.Reason) == "" {
		t.Fatal("Reason is empty, want the fallback reason so the agent is told why")
	}
}

func TestEncodeDevinResultEmitsNoDirectiveOnAllow(t *testing.T) {
	t.Parallel()

	out, err := EncodeDevinResult(hook.HookPreToolUse.String(), hook.Result{
		Decision: hook.DecisionAllow,
		Reason:   "allowed",
	})
	if err != nil {
		t.Fatalf("EncodeDevinResult() error = %v", err)
	}
	if string(out) != "{}" {
		t.Fatalf("EncodeDevinResult() = %s, want {}", out)
	}
}

// Only pre-tool-use gates a call. A deny recorded against an observation event
// must not turn into a directive Devin would act on.
func TestEncodeDevinResultNeverBlocksObservationEvents(t *testing.T) {
	t.Parallel()

	for _, name := range []hook.HookName{hook.HookPostToolUse, hook.HookSessionStart, hook.HookSessionEnd} {
		t.Run(name.String(), func(t *testing.T) {
			t.Parallel()

			out, err := EncodeDevinResult(name.String(), hook.Result{
				Decision: hook.DecisionDeny,
				Reason:   "would deny",
			})
			if err != nil {
				t.Fatalf("EncodeDevinResult() error = %v", err)
			}
			if string(out) != "{}" {
				t.Fatalf("EncodeDevinResult() = %s, want {}", out)
			}
		})
	}
}

// Devin replaces tool_input wholesale rather than merging, so a partial rewrite
// would silently drop whatever the policy did not restate. Refuse visibly.
func TestEncodeDevinResultRefusesInputRewrite(t *testing.T) {
	t.Parallel()

	out, err := EncodeDevinResult(hook.HookPreToolUse.String(), hook.Result{
		Decision:     hook.DecisionAllow,
		UpdatedInput: map[string]any{"command": "echo redacted"},
	})
	if err != nil {
		t.Fatalf("EncodeDevinResult() error = %v", err)
	}
	var decoded devinHookOutput
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", out, err)
	}
	if decoded.Decision != "block" {
		t.Fatalf("Decision = %q, want block so the request is not silently altered", decoded.Decision)
	}
	if !strings.Contains(decoded.Reason, "rewrite") {
		t.Fatalf("Reason = %q, want it to explain the refusal", decoded.Reason)
	}
}

// An unrecognized decision value must fail closed rather than letting the call
// through.
func TestEncodeDevinResultFailsClosedOnUnknownDecision(t *testing.T) {
	t.Parallel()

	out, err := EncodeDevinResult(hook.HookPreToolUse.String(), hook.Result{Decision: hook.Decision("maybe")})
	if err != nil {
		t.Fatalf("EncodeDevinResult() error = %v", err)
	}
	var decoded devinHookOutput
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(%s) error = %v", out, err)
	}
	if decoded.Decision != "block" {
		t.Fatalf("Decision = %q, want block", decoded.Decision)
	}
}
