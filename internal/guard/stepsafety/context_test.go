package stepsafety

import (
	"strings"
	"testing"
)

func TestContextStoreUsesOnlyStructuredToolHistory(t *testing.T) {
	store := NewContextStore()
	store.RecordUserRequest("s1", "update the config")
	store.RecordInteraction("s1", HistoryEntry{
		ToolName:      "get_config",
		ToolArguments: map[string]any{"file_path": "config.json"},
		ToolResponse:  map[string]any{"content": "{}"},
	})
	request, history := store.Snapshot("s1")
	if request != "update the config" {
		t.Fatalf("request = %q", request)
	}
	for _, want := range []string{`"tool":"get_config"`, `"arguments":{"file_path":"config.json"}`, `"observation":"{\"content\":\"{}\"}"`} {
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
		ToolName:      "update_config",
		ToolArguments: map[string]any{"file_path": "config.json"},
		Error:         "permission denied",
	})
	_, history := store.Snapshot("s1")
	want := `[{"arguments":{"file_path":"config.json"},"observation":"permission denied","tool":"update_config"}]`
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

func TestExcludedAndOversizedEventsDoNotEvictUsefulHistory(t *testing.T) {
	store := NewContextStore()
	store.RecordInteraction("s", HistoryEntry{ToolName: "search", ToolArguments: map[string]any{"q": "release"}})
	before := store.SnapshotWithCoverage("s")
	store.RecordInteraction("s", HistoryEntry{ToolName: "Read", ToolResponse: map[string]any{"content": strings.Repeat("x", 70*1024)}})
	store.RecordInteraction("s", HistoryEntry{ToolName: "Bash", ToolResponse: map[string]any{"stdout": strings.Repeat("x", 70*1024)}})
	after := store.SnapshotWithCoverage("s")
	if after.InteractionHistory != before.InteractionHistory || !after.HistoryOmitted {
		t.Fatalf("useful history lost: %+v", after)
	}
}

func TestStoredHistoryDoesNotRetainMutableMaps(t *testing.T) {
	store := NewContextStore()
	args := map[string]any{"q": "original"}
	store.RecordInteraction("s", HistoryEntry{ToolName: "search", ToolArguments: args})
	args["q"] = strings.Repeat("changed", 10000)
	_, history := store.Snapshot("s")
	if !strings.Contains(history, "original") || strings.Contains(history, "changed") {
		t.Fatalf("stored history changed: %s", history)
	}
}

func TestContextStoreRetainsLargeResultsForTokenTruncation(t *testing.T) {
	store := NewContextStore()
	entry := HistoryEntry{ToolName: "search", ToolResponse: map[string]any{"content": strings.Repeat("result ", 2000)}}
	store.RecordInteraction("s", entry)
	want, err := serializeHistory([]HistoryEntry{entry})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := store.SnapshotWithCoverage("s")
	if len(want) <= 4096 || snapshot.InteractionHistory != want || snapshot.HistoryOmitted {
		t.Fatalf("result discarded before token packing: length=%d, omitted=%v", len(snapshot.InteractionHistory), snapshot.HistoryOmitted)
	}
}

func TestContextStoreBoundsCombinedLargeResults(t *testing.T) {
	store := NewContextStore()
	for _, tool := range []string{"oldest", "middle", "newest"} {
		store.RecordInteraction("s", HistoryEntry{ToolName: tool, ToolResponse: map[string]any{"content": strings.Repeat("x", 24*1024)}})
	}
	snapshot := store.SnapshotWithCoverage("s")
	if len(snapshot.InteractionHistory) > maxHistoryBytes || !snapshot.HistoryOmitted || strings.Contains(snapshot.InteractionHistory, "oldest") || !strings.Contains(snapshot.InteractionHistory, "newest") {
		t.Fatalf("combined history bound: length=%d, omitted=%v", len(snapshot.InteractionHistory), snapshot.HistoryOmitted)
	}
}

func TestOversizedRequestIsNotSilentlyTruncated(t *testing.T) {
	store := NewContextStore()
	store.RecordUserRequest("s", strings.Repeat("x", maxUserRequestBytes+1))
	snapshot := store.SnapshotWithCoverage("s")
	if !snapshot.RequestTooLarge || snapshot.UserRequest != "" {
		t.Fatalf("large request was truncated/retained: %+v", snapshot)
	}
	store.RecordUserRequest("s", "new request")
	snapshot = store.SnapshotWithCoverage("s")
	if snapshot.RequestTooLarge || snapshot.UserRequest != "new request" {
		t.Fatalf("request did not reset: %+v", snapshot)
	}
}
