package stepsafety

import (
	"strings"
	"testing"
)

func TestContextStoreUsesOnlyStructuredToolHistory(t *testing.T) {
	store := NewContextStore()
	store.RecordUserRequest("s1", "update the config")
	store.RecordInteraction("s1", HistoryEntry{
		ToolName:      "Read",
		ToolArguments: map[string]any{"file_path": "config.json"},
		ToolResponse:  map[string]any{"content": "{}"},
	})
	request, history := store.Snapshot("s1")
	if request != "update the config" {
		t.Fatalf("request = %q", request)
	}
	for _, want := range []string{`"tool_name":"Read"`, `"file_path":"config.json"`, `"content":"{}"`} {
		if !strings.Contains(history, want) {
			t.Fatalf("history %q missing %q", history, want)
		}
	}
	if strings.Contains(strings.ToLower(history), "thought") {
		t.Fatalf("structured history unexpectedly contains Thought: %s", history)
	}
}

func TestContextStoreClosesSession(t *testing.T) {
	store := NewContextStore()
	store.RecordUserRequest("s1", "request")
	store.CloseSession("s1")
	request, history := store.Snapshot("s1")
	if request != "" || history != "" {
		t.Fatalf("closed context = %q / %q", request, history)
	}
}
