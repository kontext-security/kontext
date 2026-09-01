package stepsafety

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type historyGoldenFixture struct {
	SchemaVersion  int                 `json:"schema_version"`
	SourceRevision string              `json:"source_revision"`
	Cases          []historyGoldenCase `json:"cases"`
}

type historyGoldenCase struct {
	Name                           string               `json:"name"`
	ProductionEntries              []historyGoldenEntry `json:"production_entries"`
	GeneratedLongObservationTokens int                  `json:"generated_long_observation_tokens"`
	NormalizedHistory              string               `json:"normalized_history"`
	NormalizedHistorySHA256        string               `json:"normalized_history_sha256"`
}

type historyGoldenEntry struct {
	ToolName      string         `json:"tool_name"`
	ToolArguments map[string]any `json:"tool_arguments"`
	ToolResponse  map[string]any `json:"tool_response"`
	Error         string         `json:"error"`
}

func TestProductionHistoryMatchesToolSafeGolden(t *testing.T) {
	fixture := loadHistoryGoldenFixture(t)
	if fixture.SchemaVersion != 1 || fixture.SourceRevision != sourceRevision {
		t.Fatalf("fixture provenance = version %d revision %q", fixture.SchemaVersion, fixture.SourceRevision)
	}
	wantCases := map[string]bool{
		"empty_history":                 false,
		"multiple_calls":                false,
		"nested_arguments_and_response": false,
		"error_observation":             false,
		"unicode":                       false,
		"missing_fields":                false,
		"history_head_tail_truncation":  false,
	}
	for _, testCase := range fixture.Cases {
		t.Run(testCase.Name, func(t *testing.T) {
			wantCases[testCase.Name] = true
			entries := make([]HistoryEntry, 0, len(testCase.ProductionEntries))
			for _, entry := range testCase.ProductionEntries {
				entries = append(entries, HistoryEntry{
					ToolName:      entry.ToolName,
					ToolArguments: entry.ToolArguments,
					ToolResponse:  entry.ToolResponse,
					Error:         entry.Error,
				})
			}
			if testCase.GeneratedLongObservationTokens > 0 {
				entries = generatedLongObservation(testCase.GeneratedLongObservationTokens)
			}
			got, err := serializeHistory(entries)
			if err != nil {
				t.Fatal(err)
			}
			if testCase.NormalizedHistory != "" && got != testCase.NormalizedHistory {
				t.Fatalf("history mismatch\n got: %s\nwant: %s", got, testCase.NormalizedHistory)
			}
			if testCase.NormalizedHistorySHA256 != "" && sha256String(got) != testCase.NormalizedHistorySHA256 {
				t.Fatalf("history SHA-256 = %s, want %s", sha256String(got), testCase.NormalizedHistorySHA256)
			}
			if strings.Contains(strings.ToLower(got), "thought") {
				t.Fatalf("Thought leaked into production history: %s", got)
			}
		})
	}
	for name, seen := range wantCases {
		if !seen {
			t.Errorf("golden case %q is missing", name)
		}
	}
}

func loadHistoryGoldenFixture(t *testing.T) historyGoldenFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/history_serialization_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var fixture historyGoldenFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func generatedLongObservation(tokenCount int) []HistoryEntry {
	tokens := make([]string, tokenCount)
	for index := range tokens {
		tokens[index] = fmt.Sprintf("event-token-%03d", index)
	}
	return []HistoryEntry{{
		ToolName:      "Read",
		ToolArguments: map[string]any{"file_path": "large.log"},
		ToolResponse: map[string]any{
			"content": "prefix " + strings.Join(tokens, " ") + " suffix",
			"status":  "complete",
		},
	}}
}

func sha256String(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
