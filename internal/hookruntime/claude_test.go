package hookruntime

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

func TestDecodeClaudeEventUserPromptSubmitPreservesPrompt(t *testing.T) {
	t.Parallel()
	event, err := DecodeClaudeEvent([]byte(`{"session_id":"s1","hook_event_name":"UserPromptSubmit","prompt":"ship it"}`), "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent() error = %v", err)
	}
	if event.Prompt != "ship it" || event.ToolInput["prompt"] != "ship it" {
		t.Fatalf("event = %+v, want first-class prompt and compatibility mirror", event)
	}
}

func TestEncodeClaudeUserPromptSubmitDenyBlocks(t *testing.T) {
	t.Parallel()
	out, err := EncodeClaudeResult("UserPromptSubmit", hook.Result{Decision: hook.DecisionDeny, Reason: "policy unavailable"})
	if err != nil {
		t.Fatalf("EncodeClaudeResult() error = %v", err)
	}
	if text := string(out); !strings.Contains(text, `"decision":"block"`) || !strings.Contains(text, "policy unavailable") {
		t.Fatalf("EncodeClaudeResult() = %s, want top-level block", text)
	}
}

func TestDecodeClaudeEventToolResponseObject(t *testing.T) {
	t.Parallel()

	input := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"ok","stderr":""}}`)
	ev, err := DecodeClaudeEvent(input, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent() error = %v", err)
	}
	if got := ev.ToolResponse["stdout"]; got != "ok" {
		t.Fatalf("ToolResponse[stdout] = %v, want \"ok\"", got)
	}
}

func TestDecodeClaudeEventToolResponseArray(t *testing.T) {
	t.Parallel()

	// MCP tools (e.g. Linear) return tool_response as an array of content blocks.
	input := []byte(`{"hook_event_name":"PostToolUse","tool_name":"mcp__linear__get_issue","tool_response":[{"type":"text","text":"hello"}]}`)
	ev, err := DecodeClaudeEvent(input, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent() error = %v, array tool_response must not break decoding", err)
	}
	content, ok := ev.ToolResponse["content"].([]any)
	if !ok {
		t.Fatalf("ToolResponse[content] type = %T, want []any", ev.ToolResponse["content"])
	}
	if len(content) != 1 {
		t.Fatalf("len(content) = %d, want 1", len(content))
	}
}

func TestDecodeClaudeEventToolResponsePreservesLargeNumbers(t *testing.T) {
	t.Parallel()

	// Large IDs must not be rounded through float64, for both array (MCP) and
	// object (built-in) payloads.
	arrInput := []byte(`{"hook_event_name":"PostToolUse","tool_name":"mcp__x__get","tool_response":[{"id":9007199254740993}]}`)
	arrEv, err := DecodeClaudeEvent(arrInput, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent(array) error = %v", err)
	}
	arrID := arrEv.ToolResponse["content"].([]any)[0].(map[string]any)["id"]
	if num, ok := arrID.(json.Number); !ok || num.String() != "9007199254740993" {
		t.Fatalf("array id = %v (%T), want json.Number 9007199254740993", arrID, arrID)
	}

	objInput := []byte(`{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"id":9007199254740993}}`)
	objEv, err := DecodeClaudeEvent(objInput, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent(object) error = %v", err)
	}
	objID := objEv.ToolResponse["id"]
	if num, ok := objID.(json.Number); !ok || num.String() != "9007199254740993" {
		t.Fatalf("object id = %v (%T), want json.Number 9007199254740993", objID, objID)
	}
}

func TestDecodeClaudeEventToolInputPreservesNumbers(t *testing.T) {
	t.Parallel()

	input := []byte(`{"hook_event_name":"PreToolUse","tool_name":"CustomTool","tool_input":{"risk":1.25,"id":9007199254740993}}`)
	event, err := DecodeClaudeEvent(input, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent() error = %v", err)
	}
	if number, ok := event.ToolInput["risk"].(json.Number); !ok || number.String() != "1.25" {
		t.Fatalf("ToolInput[risk] = %v (%T), want json.Number 1.25", event.ToolInput["risk"], event.ToolInput["risk"])
	}
	if number, ok := event.ToolInput["id"].(json.Number); !ok || number.String() != "9007199254740993" {
		t.Fatalf("ToolInput[id] = %v (%T), want exact json.Number", event.ToolInput["id"], event.ToolInput["id"])
	}
}

func TestDecodeClaudeEventRejectsTrailingJSON(t *testing.T) {
	t.Parallel()

	input := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"} {}`)
	if _, err := DecodeClaudeEvent(input, "claude"); err == nil {
		t.Fatal("DecodeClaudeEvent() error = nil, want trailing JSON rejection")
	}
}

func TestDecodeClaudeEventToolResponseAbsent(t *testing.T) {
	t.Parallel()

	input := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	ev, err := DecodeClaudeEvent(input, "claude")
	if err != nil {
		t.Fatalf("DecodeClaudeEvent() error = %v", err)
	}
	if ev.ToolResponse != nil {
		t.Fatalf("ToolResponse = %v, want nil", ev.ToolResponse)
	}
}
