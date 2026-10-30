package modelusage

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestReadClaudeConversation(t *testing.T) {
	transcript := strings.Join([]string{
		// A partial first line, as a read from the middle of a file starts.
		`rtial","message":{}}`,
		`{"type":"user","message":{"role":"user","content":"<system-reminder>context</system-reminder>\nShorten the build"}}`,
		`{"type":"user","isMeta":true,"message":{"role":"user","content":"Caveat: local command"}}`,
		`{"type":"assistant","message":{"id":"m1","model":"claude-opus-5-5","content":[{"type":"thinking","thinking":"plan"},{"type":"text","text":"Reading the Makefile."}]}}`,
		`{"type":"assistant","message":{"id":"m1","model":"claude-opus-5-5","content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/r/Makefile"}}]}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":[{"type":"text","text":"all: build"},{"type":"image","source":{}}]}]}}`,
		`{"type":"assistant","isSidechain":true,"message":{"id":"s1","model":"claude-haiku-5-5","content":[{"type":"text","text":"subagent"}]}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"text","text":"<task-notification>done</task-notification>"}]}}`,
		`{"type":"assistant","message":{"id":"m2","model":"<synthetic>","content":[{"type":"text","text":"API error"}]}}`,
		`{"type":"summary","summary":"ignored"}`,
	}, "\n")
	got := ReadClaudeConversation(strings.NewReader(transcript), false)
	want := Conversation{Model: "claude-opus-5-5", Messages: []Message{
		{Role: "user", Text: "Shorten the build", Prompt: true},
		{Role: "assistant", Text: "Reading the Makefile.", Response: "m1"},
		{Role: "assistant", Response: "m1", ToolCall: &ToolCall{ID: "t1", Name: "Read", Input: json.RawMessage(`{"file_path":"/r/Makefile"}`)}},
		{Role: "tool", Text: "all: build\n[image]", ToolUseID: "t1"},
		{Role: "user", Text: "<task-notification>done</task-notification>"},
		{Role: "assistant", Text: "API error", Response: "m2"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadClaudeConversation() =\n%+v\nwant\n%+v", got, want)
	}

	own := strings.Join([]string{
		`{"type":"user","isSidechain":true,"message":{"role":"user","content":"Find the build target"}}`,
		`{"type":"assistant","isSidechain":true,"message":{"id":"s1","model":"claude-haiku-5-5","content":[{"type":"text","text":"Searching."}]}}`,
	}, "\n")
	subagent := ReadClaudeConversation(strings.NewReader(own), true)
	if len(subagent.Messages) != 2 || subagent.Messages[0].Text != "Find the build target" || subagent.Messages[1].Text != "Searching." || subagent.Model != "claude-haiku-5-5" {
		t.Fatalf("subagent conversation = %+v", subagent)
	}
}

func TestReadCodexConversation(t *testing.T) {
	rollout := strings.Join([]string{
		`{"type":"session_meta","payload":{"id":"th1"}}`,
		`{"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"system"}]}}`,
		`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>cwd</environment_context>"}]}}`,
		`{"type":"turn_context","payload":{"model":"gpt-6.1-sol"}}`,
		`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Old prompt"}]}}`,
		`{"type":"compacted","payload":{"message":"","replacement_history":[{"type":"message","role":"user","content":[{"type":"input_text","text":"Find the slow test"}]}]}}`,
		`{"type":"response_item","payload":{"type":"reasoning","summary":[]}}`,
		`{"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Timing the suite."}]}}`,
		`{"type":"response_item","payload":{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"go test ./...\"}","call_id":"c1"}}`,
		`{"type":"event_msg","payload":{"type":"agent_message","message":"Timing the suite."}}`,
		`{"type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":[{"type":"input_text","text":"ok  pkg 9.1s"}]}}`,
		`{"type":"response_item","payload":{"type":"custom_tool_call","name":"apply_patch","input":"*** Begin Patch","call_id":"c2"}}`,
		`{"type":"response_item","payload":{"type":"custom_tool_call_output","call_id":"c2","output":"Done"}}`,
	}, "\n")
	got := ReadCodexConversation(strings.NewReader(rollout))
	want := Conversation{Model: "gpt-6.1-sol", Compacted: true, Messages: []Message{
		{Role: "user", Text: "Find the slow test", Prompt: true},
		{Role: "assistant", Text: "Timing the suite.", Response: "1"},
		{Role: "assistant", Response: "1", ToolCall: &ToolCall{ID: "c1", Name: "exec_command", Input: json.RawMessage(`{"cmd":"go test ./..."}`)}},
		{Role: "tool", Text: "ok  pkg 9.1s", ToolUseID: "c1"},
		{Role: "assistant", Response: "2", ToolCall: &ToolCall{ID: "c2", Name: "apply_patch", Input: json.RawMessage(`"*** Begin Patch"`)}},
		{Role: "tool", Text: "Done", ToolUseID: "c2"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadCodexConversation() =\n%+v\nwant\n%+v", got, want)
	}
}

// A compaction starts the model's view over: what came before is gone.
func TestReadClaudeConversationStartsAfterACompaction(t *testing.T) {
	transcript := strings.Join([]string{
		`{"type":"user","message":{"role":"user","content":"Before the compaction"}}`,
		`{"type":"system","subtype":"compact_boundary","content":"Conversation compacted"}`,
		`{"type":"user","isCompactSummary":true,"isVisibleInTranscriptOnly":true,"message":{"role":"user","content":"Summary"}}`,
		`{"type":"user","message":{"role":"user","content":"After it"}}`,
	}, "\n")
	got := ReadClaudeConversation(strings.NewReader(transcript), false)
	if !got.Compacted || len(got.Messages) != 1 || got.Messages[0].Text != "After it" {
		t.Fatalf("ReadClaudeConversation() = %+v", got)
	}
	if plain := ReadClaudeConversation(strings.NewReader(`{"type":"user","message":{"role":"user","content":"x"}}`), false); plain.Compacted {
		t.Fatal("a read without a compaction is marked compacted")
	}
}
