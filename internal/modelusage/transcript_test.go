package modelusage

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
)

type transcriptCase struct {
	name  string
	start func() *Transcript
	raw   string
}

func transcriptCases(t *testing.T) []transcriptCase {
	t.Helper()
	read := func(path string) string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	claude := read("testdata/claude-code-2.1.271.jsonl")
	codex := read("testdata/codex-tool-turn.jsonl")
	// One message streamed as several snapshots, results consumed across
	// lines, metadata enriched late, and an ordinary prompt clearing results.
	snapshots := `{"type":"assistant","sessionId":"s","requestId":"r","timestamp":"2026-09-16T13:36:44Z","message":{"id":"a","model":"claude","content":[{"type":"tool_use","id":"t1"}],"usage":{"input_tokens":2,"output_tokens":5}}}
{"type":"progress","message":"not an assistant message"}
{"type":"assistant","sessionId":"s","requestId":"r","message":{"id":"a","model":"claude","content":[{"type":"tool_use","id":"t2","name":"Read"},{"type":"tool_use","id":"t1","name":"Bash"}],"usage":{"output_tokens":15}}}

{"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"t1"},{"type":"tool_result","tool_use_id":"t2"}]}}
{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:45Z","message":{"id":"b","model":"claude","usage":{"output_tokens":7}}}
{"type":"assistant","sessionId":"other","timestamp":"2026-09-16T13:36:45Z","message":{"id":"b","model":"claude","content":[{"type":"tool_use","id":"t1","toolset_name":"browser"}],"usage":{"output_tokens":1}}}
{"type":"user","sessionId":"s","message":{"content":"new unrelated question"}}
{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:46Z","message":{"id":"c","model":"claude","usage":{"output_tokens":9}}}
{"type":"assistant","sessionId":"s","message":{"id":"a","model":"claude","content":[{"type":"tool_use","id":"t2","toolset_name":"files"}],"usage":{"output_tokens":16}}}
`
	codexTurns := `{"type":"session_meta","payload":{"id":"s","model_provider":"openai"}}
{"type":"turn_context","payload":{"model":"gpt-6-astra"}}
{"type":"response_item","payload":{"type":"custom_tool_call","call_id":"a","name":"exec"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"b","name":"js","namespace":"mcp__cua_repl"}}
{"timestamp":"2026-09-17T10:00:00Z","type":"token_usage_record","payload":{"thread_id":"s","response_id":"r1","usage":{"input_tokens":10,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":2}}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"a"}}
{"type":"event_msg","payload":{"type":"token_count"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"a","toolset_name":"shell"}}
{"type":"token_usage_record","payload":{"thread_id":"s","response_id":"r1","usage":{"input_tokens":10}}}
{"type":"response_item","payload":{"type":"message","role":"assistant"}}
{"timestamp":"2026-09-17T10:00:01Z","type":"token_usage_record","payload":{"thread_id":"s","response_id":"r2","usage":{"input_tokens":20,"cached_input_tokens":10,"cache_write_input_tokens":0,"output_tokens":3}}}
{"type":"event_msg","payload":{"type":"task_started"}}
{"type":"response_item","payload":{"type":"message","role":"assistant"}}
{"type":"token_usage_record","payload":{"thread_id":"parent","response_id":"r3","usage":{"input_tokens":30}}}
`
	return []transcriptCase{
		{"claude testdata", NewClaudeTranscript, claude},
		{"codex testdata", NewCodexTranscript, codex},
		{"claude snapshots", NewClaudeTranscript, snapshots},
		{"codex turns", NewCodexTranscript, codexTurns},
		{"claude without final newline", NewClaudeTranscript, strings.TrimSuffix(claude, "\n")},
		// Each failure must surface at the same prefix, and stay, as in a full read.
		{"claude conflicting identity", NewClaudeTranscript, snapshots + strings.ReplaceAll(strings.SplitAfter(snapshots, "\n")[0], `"r"`, `"other"`) + snapshots},
		{"claude negative count", NewClaudeTranscript, claude + strings.ReplaceAll(strings.SplitAfter(claude, "\n")[0], `"output_tokens":83`, `"output_tokens":-1`) + claude},
		{"codex conflicting session", NewCodexTranscript, codex + strings.ReplaceAll(strings.SplitAfter(codex, "\n")[0], "01a0afe3", "02a0afe3") + codex},
		{"codex legacy only", NewCodexTranscript, `{"type":"session_meta","payload":{"id":"s","model_provider":"openai"}}` + "\n" + `{"type":"event_msg","payload":{"type":"token_count"}}` + "\n" + codexTurns},
	}
}

type transcriptResult struct {
	records []Record
	err     string
}

func fullTranscriptRead(c transcriptCase, prefix string) transcriptResult {
	records, err := c.start().Read(strings.NewReader(prefix))
	return transcriptResult{records, fmt.Sprint(err)}
}

// readGrowing reads the transcript as it grows to each cut, as the reconciler
// does: every Read gets the bytes from the previous offset to the new size.
func readGrowing(t *testing.T, c transcriptCase, cuts []int) {
	t.Helper()
	transcript := c.start()
	for _, cut := range cuts {
		offset := transcript.Offset()
		records, err := transcript.Read(strings.NewReader(c.raw[offset:cut]))
		got := transcriptResult{records, fmt.Sprint(err)}
		if want := fullTranscriptRead(c, c.raw[:cut]); !reflect.DeepEqual(got, want) {
			t.Fatalf("cuts %v: incremental read at %d differs from full read:\n got %+v\nwant %+v", cuts, cut, got, want)
		}
		if transcript.Offset() < offset || transcript.Offset() > int64(cut) || (transcript.Offset() > 0 && c.raw[transcript.Offset()-1] != '\n') {
			t.Fatalf("cuts %v: offset %d is not the end of a complete line within %d", cuts, transcript.Offset(), cut)
		}
	}
}

func TestTranscriptIncrementalReadMatchesFullReadAtEverySplit(t *testing.T) {
	for _, c := range transcriptCases(t) {
		t.Run(c.name, func(t *testing.T) {
			for split := 0; split <= len(c.raw); split++ {
				readGrowing(t, c, []int{split, len(c.raw)})
			}
		})
	}
}

func TestTranscriptIncrementalReadMatchesFullReadAtRandomSplits(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, c := range transcriptCases(t) {
		t.Run(c.name, func(t *testing.T) {
			for range 200 {
				cuts := make([]int, 1+rng.Intn(8))
				for i := range cuts {
					cuts[i] = rng.Intn(len(c.raw) + 1)
				}
				cuts = append(cuts, len(c.raw))
				for i := 1; i < len(cuts); i++ {
					cuts[i] = max(cuts[i], cuts[i-1])
				}
				readGrowing(t, c, cuts)
			}
		})
	}
}

func TestTranscriptOffsetWaitsForCompleteLine(t *testing.T) {
	first := `{"type":"assistant","sessionId":"s","message":{"id":"m","model":"claude","content":[{"type":"tool_use","id":"t"}],"usage":{"output_tokens":1}}}` + "\n"
	last := `{"type":"assistant","sessionId":"s","message":{"id":"m","model":"claude","usage":{"output_tokens":2}}}`
	transcript := NewClaudeTranscript()
	for _, step := range []struct {
		file   string
		offset int
		output int64
	}{
		{first + last[:20], len(first), 1},
		// Valid but unterminated: counted like a full read, read again later.
		{first + last, len(first), 2},
		{first + last + "\n", len(first + last + "\n"), 2},
	} {
		records, err := transcript.Read(strings.NewReader(step.file[transcript.Offset():]))
		if err != nil || len(records) != 1 || *records[0].Tokens.Output != step.output {
			t.Fatalf("after %q: %+v %v", step.file, records, err)
		}
		if transcript.Offset() != int64(step.offset) {
			t.Fatalf("after %q: offset %d, want %d", step.file, transcript.Offset(), step.offset)
		}
	}
}
