package localruntime

import (
	"encoding/json"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

func TestEvaluateRequestFromEventPreservesHookFields(t *testing.T) {
	t.Parallel()

	duration := int64(42)
	interrupted := false
	req, err := EvaluateRequestFromEvent(hook.Event{
		Agent:          "claude",
		HookName:       hook.HookPostToolUseFailed,
		ToolName:       "Bash",
		ToolInput:      map[string]any{"command": "npm test"},
		ToolResponse:   map[string]any{"stderr": "failed"},
		ToolUseID:      "toolu_123",
		CWD:            "/tmp/project",
		PermissionMode: "default",
		DurationMs:     &duration,
		Error:          "command failed",
		IsInterrupt:    &interrupted,
	})
	if err != nil {
		t.Fatalf("EvaluateRequestFromEvent() error = %v", err)
	}

	if req.Type != "evaluate" ||
		req.Agent != "claude" ||
		req.HookEvent != "PostToolUseFailure" ||
		req.ToolName != "Bash" ||
		req.ToolUseID != "toolu_123" ||
		req.CWD != "/tmp/project" ||
		req.PermissionMode != "default" ||
		req.DurationMs == nil ||
		*req.DurationMs != 42 ||
		req.Error != "command failed" ||
		req.IsInterrupt == nil ||
		*req.IsInterrupt {
		t.Fatalf("request = %+v, want event fields preserved", req)
	}
	if !json.Valid(req.ToolInput) || !json.Valid(req.ToolResponse) {
		t.Fatalf("tool payloads must be valid JSON: input=%s response=%s", req.ToolInput, req.ToolResponse)
	}
}

func TestEventFromEvaluateRequestPreservesHookFields(t *testing.T) {
	t.Parallel()

	duration := int64(0)
	interrupted := false
	event, err := EventFromEvaluateRequest("session-123", "fallback-agent", &EvaluateRequest{
		Agent:          "claude",
		HookEvent:      "PostToolUseFailure",
		ToolName:       "Bash",
		ToolInput:      json.RawMessage(`{"command":"npm test"}`),
		ToolResponse:   json.RawMessage(`{"stderr":"failed"}`),
		ToolUseID:      "toolu_123",
		CWD:            "/tmp/project",
		PermissionMode: "default",
		DurationMs:     &duration,
		Error:          "command failed",
		IsInterrupt:    &interrupted,
	})
	if err != nil {
		t.Fatalf("EventFromEvaluateRequest() error = %v", err)
	}

	if event.SessionID != "session-123" ||
		event.Agent != "claude" ||
		event.HookName != hook.HookPostToolUseFailed ||
		event.ToolName != "Bash" ||
		event.ToolInput["command"] != "npm test" ||
		event.ToolResponse["stderr"] != "failed" ||
		event.ToolUseID != "toolu_123" ||
		event.CWD != "/tmp/project" ||
		event.PermissionMode != "default" ||
		event.DurationMs == nil ||
		*event.DurationMs != 0 ||
		event.Error != "command failed" ||
		event.IsInterrupt == nil ||
		*event.IsInterrupt {
		t.Fatalf("event = %+v, want request fields preserved", event)
	}
}

func TestEventFromEvaluateRequestRejectsMissingHookEvent(t *testing.T) {
	t.Parallel()

	_, err := EventFromEvaluateRequest("session-123", "claude", &EvaluateRequest{ToolName: "Bash"})
	if err == nil {
		t.Fatal("EventFromEvaluateRequest() error = nil, want missing hook event error")
	}
}

func TestEventFromEvaluateRequestRejectsUnknownHookEvent(t *testing.T) {
	t.Parallel()

	_, err := EventFromEvaluateRequest("session-123", "claude", &EvaluateRequest{HookEvent: "pretooluse", ToolName: "Bash"})
	if err == nil {
		t.Fatal("EventFromEvaluateRequest() error = nil, want unknown hook event error")
	}
}

func TestEventFromEvaluateRequestPreservesLargeJSONNumbers(t *testing.T) {
	t.Parallel()

	event, err := EventFromEvaluateRequest("session-123", "claude", &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"id":9007199254740993}`),
	})
	if err != nil {
		t.Fatalf("EventFromEvaluateRequest() error = %v", err)
	}
	got, ok := event.ToolInput["id"].(json.Number)
	if !ok {
		t.Fatalf("id type = %T, want json.Number", event.ToolInput["id"])
	}
	if got.String() != "9007199254740993" {
		t.Fatalf("id = %s, want exact large number", got.String())
	}
}

func TestResultFromEvaluateResultNormalizesLegacyDecision(t *testing.T) {
	t.Parallel()

	result := ResultFromEvaluateResult(EvaluateResult{
		Decision:  "DENY",
		Allowed:   true,
		Reason:    "blocked",
		RequestID: "req-123",
	})

	if result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %q, want deny", result.Decision)
	}
	if result.RequestID != "req-123" {
		t.Fatalf("request id = %q, want req-123", result.RequestID)
	}
}

func TestResultFromEvaluateResultFallsBackToAllowedFlag(t *testing.T) {
	t.Parallel()

	result := ResultFromEvaluateResult(EvaluateResult{
		Decision: "unexpected",
		Allowed:  true,
		Reason:   "legacy allow",
	})

	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want allow", result.Decision)
	}
}
