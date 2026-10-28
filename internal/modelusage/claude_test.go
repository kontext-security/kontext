package modelusage

import (
	"os"
	"slices"
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

// Claude Code 2.1.229 logged a refused claude-fable-5 attempt and the
// claude-opus-4-8 fallback with the final write total but the first split.
func TestReadClaudeTranscriptCacheSplitAfterFallback(t *testing.T) {
	const fallback = `{"type":"assistant","sessionId":"s","requestId":"r","message":{"id":"m","model":"claude-opus-4-8","content":[{"type":"tool_use","id":"t1"}],"usage":{"input_tokens":2,"cache_creation_input_tokens":494190,"cache_read_input_tokens":64310,"output_tokens":2039,"cache_creation":{"ephemeral_1h_input_tokens":528936,"ephemeral_5m_input_tokens":0},"iterations":[{"input_tokens":2,"output_tokens":3406,"cache_read_input_tokens":32155,"cache_creation_input_tokens":528936,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":528936},"type":"message","model":"claude-fable-5"},{"input_tokens":2,"output_tokens":2039,"cache_read_input_tokens":64310,"cache_creation_input_tokens":494190,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":494190},"type":"fallback_message","model":"claude-opus-4-8"}]}}}
`
	records, err := ReadClaudeTranscript(strings.NewReader(fallback + fallback))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want the message and its refused attempt", len(records))
	}
	if got := records[0].Tokens; *got.InputCacheWrite != 494190 || *got.CacheWrite5m != 0 || *got.CacheWrite1h != 494190 {
		t.Fatalf("split should come from the attempt that produced the message: %+v", got)
	}
	// The refused attempt produced output, so it's billed on its own at its
	// own model's rates, under the same request and tool links.
	attempt := records[1]
	if attempt.MessageID != "m#iteration-0" || attempt.Model != "claude-fable-5" || attempt.RequestID != "r" ||
		!slices.Equal(attempt.ToolUseIDs, []string{"t1"}) || len(attempt.Tools) != 1 {
		t.Fatalf("refused attempt identity: %+v", attempt)
	}
	if got := attempt.Tokens; *got.InputUncached != 2 || *got.InputCacheRead != 32155 || *got.InputCacheWrite != 528936 ||
		*got.CacheWrite5m != 0 || *got.CacheWrite1h != 528936 || *got.Output != 3406 || got.Thinking != nil {
		t.Fatalf("refused attempt tokens: %+v", got)
	}

	// An attempt refused before any output is billed only for some refusal
	// categories, which the transcript doesn't record.
	beforeOutput := strings.Replace(fallback, `"output_tokens":3406`, `"output_tokens":0`, 1)
	records, err = ReadClaudeTranscript(strings.NewReader(beforeOutput))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want only the message", len(records))
	}

	// No attempt matches the total. A split below it reports part of the
	// write and is kept as reported; one above it contradicts the total.
	const consistent = `{"type":"assistant","sessionId":"s","requestId":"r","message":{"id":"m","model":"claude","content":[{"type":"tool_use","id":"t1"}],"usage":{"cache_creation_input_tokens":10,"cache_creation":{"ephemeral_5m_input_tokens":10,"ephemeral_1h_input_tokens":0}}}}
`
	const partial = `{"type":"assistant","sessionId":"s","requestId":"r","message":{"id":"m","model":"claude","content":[{"type":"tool_use","id":"t1"}],"usage":{"cache_creation_input_tokens":12,"cache_creation":{"ephemeral_5m_input_tokens":10,"ephemeral_1h_input_tokens":0},"iterations":[{"cache_creation_input_tokens":10,"cache_creation":{"ephemeral_5m_input_tokens":10,"ephemeral_1h_input_tokens":0}}]}}}
`
	records, err = ReadClaudeTranscript(strings.NewReader(consistent + partial))
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0].Tokens; *got.InputCacheWrite != 12 || *got.CacheWrite5m != 10 || *got.CacheWrite1h != 0 {
		t.Fatalf("a split below the total should be kept as reported: %+v", got)
	}
	records, err = ReadClaudeTranscript(strings.NewReader(consistent + strings.Replace(partial, `"cache_creation_input_tokens":12`, `"cache_creation_input_tokens":8`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0].Tokens; *got.InputCacheWrite != 8 || got.CacheWrite5m != nil || got.CacheWrite1h != nil {
		t.Fatalf("a split above the total is unknown: %+v", got)
	}
	// Counts whose sum overflows int64 still exceed the total.
	overflow := strings.Replace(partial, `"ephemeral_5m_input_tokens":10,"ephemeral_1h_input_tokens":0},"iterations"`, `"ephemeral_5m_input_tokens":9223372036854775807,"ephemeral_1h_input_tokens":2},"iterations"`, 1)
	records, err = ReadClaudeTranscript(strings.NewReader(overflow))
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0].Tokens; got.CacheWrite5m != nil || got.CacheWrite1h != nil {
		t.Fatalf("an overflowing split is unknown: %+v", got)
	}

	// The attempt that produced the message supplies its split even when it
	// names a lifetime for only part of the write.
	const partialAttempt = `{"type":"assistant","sessionId":"s","requestId":"r","message":{"id":"m","model":"claude","content":[{"type":"tool_use","id":"t1"}],"usage":{"cache_creation_input_tokens":12,"cache_creation":{"ephemeral_5m_input_tokens":20,"ephemeral_1h_input_tokens":0},"iterations":[{"type":"message","cache_creation_input_tokens":20,"cache_creation":{"ephemeral_5m_input_tokens":20,"ephemeral_1h_input_tokens":0}},{"type":"fallback_message","cache_creation_input_tokens":12,"cache_creation":{"ephemeral_5m_input_tokens":0,"ephemeral_1h_input_tokens":5}}]}}}
`
	records, err = ReadClaudeTranscript(strings.NewReader(partialAttempt))
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0].Tokens; *got.InputCacheWrite != 12 || got.CacheWrite5m == nil || *got.CacheWrite5m != 0 || got.CacheWrite1h == nil || *got.CacheWrite1h != 5 {
		t.Fatalf("a partial split should come from the attempt that produced the message: %+v", got)
	}

	// Snapshots of one message don't all list iterations. One that doesn't
	// keeps the recovered split and the refused attempt.
	noIterations := fallback[:strings.Index(fallback, `,"iterations"`)] + "}}}\n"
	records, err = ReadClaudeTranscript(strings.NewReader(fallback + noIterations))
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0].Tokens; len(records) != 2 || *got.CacheWrite5m != 0 || *got.CacheWrite1h != 494190 {
		t.Fatalf("a snapshot without iterations should keep what an earlier one recovered: %d records, %+v", len(records), got)
	}

	// A later total without a split keeps the earlier split while it's part
	// of the new total, and drops it once it exceeds that total.
	const newTotal = `{"type":"assistant","sessionId":"s","requestId":"r","message":{"id":"m","model":"claude-opus-4-8","content":[],"usage":{"cache_creation_input_tokens":500000}}}
`
	records, err = ReadClaudeTranscript(strings.NewReader(fallback + newTotal))
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0].Tokens; *got.InputCacheWrite != 500000 || *got.CacheWrite5m != 0 || *got.CacheWrite1h != 494190 {
		t.Fatalf("a kept split below the latest total should stay: %+v", got)
	}
	records, err = ReadClaudeTranscript(strings.NewReader(fallback + strings.Replace(newTotal, "500000", "400000", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0].Tokens; *got.InputCacheWrite != 400000 || got.CacheWrite5m != nil || got.CacheWrite1h != nil {
		t.Fatalf("a kept split must not exceed the latest total: %+v", got)
	}

	// A snapshot reporting one lifetime replaces the whole split, rather than
	// summing with the other lifetime an earlier snapshot reported.
	const fiveMinutes = `{"type":"assistant","sessionId":"s","requestId":"r","message":{"id":"m","model":"claude","content":[{"type":"tool_use","id":"t1"}],"usage":{"cache_creation_input_tokens":10,"cache_creation":{"ephemeral_5m_input_tokens":10}}}}
`
	const oneHour = `{"type":"assistant","sessionId":"s","requestId":"r","message":{"id":"m","model":"claude","content":[],"usage":{"cache_creation":{"ephemeral_1h_input_tokens":10}}}}
`
	records, err = ReadClaudeTranscript(strings.NewReader(fiveMinutes + oneHour))
	if err != nil {
		t.Fatal(err)
	}
	if got := records[0].Tokens; *got.InputCacheWrite != 10 || got.CacheWrite5m != nil || got.CacheWrite1h == nil || *got.CacheWrite1h != 10 {
		t.Fatalf("a later split should replace an earlier one: %+v", got)
	}

	// A snapshot listing iterations without the attempt withdraws its usage,
	// so an upload already made is replaced by zero.
	records, err = ReadClaudeTranscript(strings.NewReader(fallback + beforeOutput))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want the message and the withdrawn attempt", len(records))
	}
	for _, count := range records[1].Tokens.fields() {
		if *count != nil && **count != 0 {
			t.Fatalf("withdrawn attempt still has usage: %+v", records[1].Tokens)
		}
	}
	if records[1].Tokens.Output == nil {
		t.Fatal("withdrawn attempt should report zero output, not unknown")
	}

	// The suffix never pushes an ID past the API's message ID limit.
	long := strings.Repeat("m", maxMessageID-5)
	records, err = ReadClaudeTranscript(strings.NewReader(strings.Replace(fallback, `"id":"m"`, `"id":"`+long+`"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if id := records[1].MessageID; len(id) > maxMessageID || !strings.HasSuffix(id, "#iteration-0") || id == long+"#iteration-0" {
		t.Fatalf("attempt ID %q exceeds the limit", id)
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
