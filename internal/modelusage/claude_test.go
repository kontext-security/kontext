package modelusage

import (
	"os"
	"strings"
	"testing"
)

func TestReadClaudeTranscriptLiveProbe(t *testing.T) {
	f, err := os.Open("testdata/claude-code-2.1.271.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	records, err := ReadClaudeTranscript(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want tool generation and final response", len(records))
	}
	var input, output, writes, reads int64
	for _, record := range records {
		if record.Model != "claude-fable-5-1" || record.ServiceTier != "standard" || record.RequestID == "" {
			t.Fatalf("lost pricing/identity metadata: %+v", record)
		}
		tokens := record.Tokens
		input += *tokens.InputUncached + *tokens.InputCacheRead + *tokens.InputCacheWrite
		output += *tokens.Output
		writes += *tokens.CacheWrite1h
		reads += *tokens.InputCacheRead
		if tokens.CacheWrite5m == nil || *tokens.CacheWrite5m != 0 || tokens.Thinking == nil || *tokens.Thinking != 0 {
			t.Fatalf("reported zero values must survive: %+v", tokens)
		}
	}
	if input != 104185 || output != 87 || writes != 17391 || reads != 86760 {
		t.Fatalf("unexpected totals: input=%d output=%d writes=%d reads=%d", input, output, writes, reads)
	}
	if len(records[0].ToolUseIDs) != 1 || len(records[1].ToolUseIDs) != 0 {
		t.Fatalf("incorrect tool association: %+v", records)
	}
	if !records[1].ToolRelated() || len(records[1].ConsumedToolUseIDs) != 1 || records[1].Tools[0].Name != "Bash" {
		t.Fatalf("final response must consume the preceding tool result: %+v", records[1])
	}
}

func TestToolScopeIncludesSharedRequestsButNotOrdinaryConversation(t *testing.T) {
	input := `{"type":"assistant","sessionId":"s","message":{"id":"a","model":"claude","content":[{"type":"tool_use","id":"t1"},{"type":"tool_use","id":"t2","name":"Read"}],"usage":{"output_tokens":5}}}
{"type":"assistant","sessionId":"s","message":{"id":"a","model":"claude","content":[{"type":"tool_use","id":"t1","name":"Bash"}],"usage":{"output_tokens":10}}}
{"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"t1"},{"type":"tool_result","tool_use_id":"t1"}]}}
{"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"t2"}]}}
{"type":"assistant","sessionId":"s","message":{"id":"b","model":"claude","usage":{"output_tokens":7}}}
{"type":"assistant","sessionId":"s","message":{"id":"c","model":"claude","usage":{"output_tokens":9}}}
{"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"t1"}]}}
{"type":"user","sessionId":"s","message":{"content":"new unrelated question"}}
{"type":"assistant","sessionId":"s","message":{"id":"d","model":"claude","usage":{"output_tokens":11}}}
`
	records, err := ReadClaudeTranscript(strings.NewReader(input))
	if err != nil || len(records) != 4 {
		t.Fatalf("records: %+v, %v", records, err)
	}
	if len(records[0].Tools) != 2 || records[0].Tools[0].Name != "Bash" || *records[0].Tokens.Output != 10 {
		t.Fatalf("shared request must count once and preserve late tool names: %+v", records[0])
	}
	if len(records[1].ConsumedToolUseIDs) != 2 || len(records[1].Tools) != 2 {
		t.Fatalf("result consumer must link unique tools: %+v", records[1])
	}
	if records[2].ToolRelated() || records[3].ToolRelated() {
		t.Fatal("ordinary conversation must stay outside tool scope")
	}
}

func TestReadClaudeTranscriptMergesMessageSnapshots(t *testing.T) {
	input := `{"type":"user","message":{"content":"do a test"}}
{"type":"progress","message":"not an assistant message"}
{"type":"assistant","sessionId":"s","requestId":"r","message":{"id":"m","model":"claude","content":[{"type":"tool_use","id":"t1"}],"usage":{"input_tokens":2,"cache_read_input_tokens":20,"cache_creation_input_tokens":10,"output_tokens":5}}}
{"type":"assistant","sessionId":"s","requestId":"r","message":{"id":"m","model":"claude","content":[{"type":"tool_use","id":"t2"},{"type":"tool_use","id":"t1"}],"usage":{"output_tokens":15,"output_tokens_details":{"thinking_tokens":4}}}}
`
	records, err := ReadClaudeTranscript(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want one model message", len(records))
	}
	r := records[0]
	if *r.Tokens.InputUncached != 2 || *r.Tokens.Output != 15 || *r.Tokens.Thinking != 4 || len(r.ToolUseIDs) != 2 {
		t.Fatalf("snapshots should update, not sum: %+v", r)
	}
	if r.Tokens.CacheWrite5m != nil || r.Tokens.CacheWrite1h != nil {
		t.Fatal("missing cache lifetime is unknown, not zero or a guessed duration")
	}
}

func TestReadClaudeTranscriptMissingUsageAndSyntheticErrors(t *testing.T) {
	input := `{"type":"assistant","message":{"model":"<synthetic>","usage":{"input_tokens":0,"output_tokens":0}}}
{"type":"assistant","sessionId":"s","message":{"id":"m1","model":"claude"}}
{"type":"assistant","sessionId":"s","message":{"id":"m2","model":"claude","usage":{"output_tokens":0}}}
`
	records, err := ReadClaudeTranscript(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].MessageID != "m2" {
		t.Fatalf("synthetic and missing usage must be skipped: %+v", records)
	}
	tokens := records[0].Tokens
	if tokens.Output == nil || *tokens.Output != 0 || tokens.InputUncached != nil || tokens.InputCacheRead != nil {
		t.Fatalf("missing must remain distinct from zero: %+v", tokens)
	}
}

func TestReadClaudeTranscriptWaitsForCompleteTrailingLine(t *testing.T) {
	line := `{"type":"assistant","sessionId":"s","message":{"id":"m","model":"claude","usage":{"output_tokens":1}}}`
	for _, tail := range []string{line[:len(line)/2], line[:len(line)-1]} {
		records, err := ReadClaudeTranscript(strings.NewReader("{}\n" + tail))
		if err != nil || len(records) != 0 {
			t.Fatalf("unfinished JSONL record: got %+v, %v", records, err)
		}
	}
	for _, ending := range []string{"", "\n"} {
		records, err := ReadClaudeTranscript(strings.NewReader(line + ending))
		if err != nil || len(records) != 1 {
			t.Fatalf("completed line: got %+v, %v", records, err)
		}
	}
}

func TestReadClaudeTranscriptRejectsUnusableRecords(t *testing.T) {
	for name, input := range map[string]string{
		"malformed complete line": `{"type":`,
		"missing identity":        `{"type":"assistant","message":{"model":"claude","usage":{"output_tokens":1}}}`,
		"negative count":          `{"type":"assistant","sessionId":"s","message":{"id":"m","model":"claude","usage":{"output_tokens":-1}}}`,
		"fractional count":        `{"type":"assistant","sessionId":"s","message":{"id":"m","model":"claude","usage":{"output_tokens":1.5}}}`,
		"overflow":                `{"type":"assistant","sessionId":"s","message":{"id":"m","model":"claude","usage":{"output_tokens":9223372036854775808}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadClaudeTranscript(strings.NewReader(input + "\n")); err == nil {
				t.Fatal("expected invalid usage to be rejected")
			}
		})
	}
}

func TestReadClaudeTranscriptIdentityIncludesSession(t *testing.T) {
	line := `{"type":"assistant","sessionId":"SESSION","requestId":"r","message":{"id":"m","model":"claude","usage":{"output_tokens":1}}}` + "\n"
	input := strings.ReplaceAll(line, "SESSION", "s1") + strings.ReplaceAll(line, "SESSION", "s2")
	records, err := ReadClaudeTranscript(strings.NewReader(input))
	if err != nil || len(records) != 2 {
		t.Fatalf("separate sessions: got %+v, %v", records, err)
	}
	if _, err := ReadClaudeTranscript(strings.NewReader(line + strings.ReplaceAll(line, `"r"`, `"different_request"`))); err == nil {
		t.Fatal("expected conflicting message identity to be rejected")
	}
}

func TestClaudeToolMetadataSurvivesSnapshotsAndResultConsumption(t *testing.T) {
	input := `{"type":"assistant","sessionId":"s","message":{"id":"a","model":"claude","content":[{"type":"tool_use","id":"t","name":"navigate","toolset_name":"browser","input":{"url":"private"}}],"usage":{"output_tokens":5}}}
{"type":"assistant","sessionId":"s","message":{"id":"a","model":"claude","content":[{"type":"tool_use","id":"t"}],"usage":{"output_tokens":6}}}
{"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"t"}]}}
{"type":"assistant","sessionId":"s","message":{"id":"b","model":"claude","usage":{"output_tokens":7}}}
`
	rows, err := ReadClaudeTranscript(strings.NewReader(input))
	if err != nil || len(rows) != 2 {
		t.Fatalf("records: %+v, %v", rows, err)
	}
	for _, row := range rows {
		if len(row.Tools) != 1 || row.Tools[0] != (Tool{ID: "t", Name: "navigate", Type: "tool_use", ToolsetName: "browser"}) {
			t.Fatalf("lost toolset identity: %+v", row.Tools)
		}
	}
}
