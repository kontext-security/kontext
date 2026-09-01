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
	for _, want := range []string{`"tool":"Read"`, `"arguments":{"file_path":"config.json"}`, `"observation":"{\"content\":\"{}\"}"`} {
		if !strings.Contains(history, want) {
			t.Fatalf("history %q missing %q", history, want)
		}
	}
	if strings.Contains(strings.ToLower(history), "thought") {
		t.Fatalf("structured history unexpectedly contains Thought: %s", history)
	}
}

func TestContextStoreUsesTrainingEmptyHistoryRepresentation(t *testing.T) {
	store := NewContextStore()
	store.RecordUserRequest("s1", "inspect the repository")
	request, history := store.Snapshot("s1")
	if request != "inspect the repository" || history != "[]" {
		t.Fatalf("empty context = %q / %q, want request / []", request, history)
	}
}

func TestContextStoreRepresentsFailuresAsObservationStrings(t *testing.T) {
	store := NewContextStore()
	store.RecordInteraction("s1", HistoryEntry{
		ToolName:      "Write",
		ToolArguments: map[string]any{"file_path": "config.json"},
		Error:         "permission denied",
	})
	_, history := store.Snapshot("s1")
	want := `[{"arguments":{"file_path":"config.json"},"observation":"permission denied","tool":"Write"}]`
	if history != want {
		t.Fatalf("failure history = %q, want %q", history, want)
	}
}

func TestCompactSortedJSONMatchesPythonUnicodeEscaping(t *testing.T) {
	got, err := compactSortedJSON(map[string]any{
		"literal": `\u2028`,
		"line":    "before\u2028middle\u2029after",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"line\":\"before\u2028middle\u2029after\",\"literal\":\"\\\\u2028\"}"
	if got != want {
		t.Fatalf("Unicode JSON = %q, want %q", got, want)
	}
}

func TestContextStoreClosesSession(t *testing.T) {
	store := NewContextStore()
	store.RecordUserRequest("s1", "request")
	store.CloseSession("s1")
	request, history := store.Snapshot("s1")
	if request != "" || history != "[]" {
		t.Fatalf("closed context = %q / %q", request, history)
	}
}
