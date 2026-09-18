package modelusage

import (
	"os"
	"strings"
	"testing"
)

func TestCodexLiveToolTurn(t *testing.T) {
	raw, err := os.ReadFile("testdata/codex-tool-turn.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	records, err := ReadCodexTranscript(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records", len(records))
	}
	a, b := records[0], records[1]
	if a.SessionID != "codex-01a0afe3-75c0-73e1-81ef-233317e1fb2c" || a.RequestID != a.MessageID {
		t.Fatalf("identity: %+v", a)
	}
	if len(a.ToolUseIDs) != 1 || len(a.ConsumedToolUseIDs) != 0 || len(b.ToolUseIDs) != 0 || len(b.ConsumedToolUseIDs) != 1 || a.ToolUseIDs[0] != b.ConsumedToolUseIDs[0] {
		t.Fatalf("associations: %+v %+v", a, b)
	}
	if *a.Tokens.InputUncached != 3321 || *b.Tokens.InputUncached != 3453 || *a.Tokens.InputCacheRead != 11008 || *a.Tokens.InputCacheWrite != 0 || *a.Tokens.Output != 91 || *b.Tokens.Output != 16 || *a.Tokens.Thinking != 38 {
		t.Fatalf("counters: %+v %+v", a.Tokens, b.Tokens)
	}
	// A partial tail and repeated rate-limit/cumulative notifications must not add a request.
	again, err := ReadCodexTranscript(strings.NewReader(string(raw) + `{"type":"event_msg","payload":{"type":"token_count"}}` + "\n" + `{"type":`))
	if err != nil || len(again) != 2 {
		t.Fatalf("partial read: %d %v", len(again), err)
	}
	for _, variant := range []string{
		strings.ReplaceAll(string(raw), `"model_provider": "openai"`, `"model_provider": "custom"`),
		strings.ReplaceAll(string(raw), `"thread_id": "01a0afe3-75c0-73e1-81ef-233317e1fb2c"`, `"thread_id": "parent-thread"`),
	} {
		rows, err := ReadCodexTranscript(strings.NewReader(variant))
		if err != nil || len(rows) != 0 {
			t.Fatalf("foreign provider/fork: %d %v", len(rows), err)
		}
	}
}

func TestCodexTokenNormalization(t *testing.T) {
	n := func(v int64) *int64 { return &v }
	u := codexUsage{Input: n(1000), Read: n(600), Write: n(300), Output: n(20), Reasoning: n(15)}
	v, err := u.tokens()
	if err != nil || *v.InputUncached != 100 || *v.CacheWrite30m != 300 || *v.Output != 20 {
		t.Fatalf("normalization: %+v %v", v, err)
	}
	u.Write = nil
	v, err = u.tokens()
	if err != nil || v.InputUncached != nil || v.InputCacheWrite != nil {
		t.Fatal("missing is not zero")
	}
	u.Write = n(500)
	if _, err = u.tokens(); err == nil {
		t.Fatal("overlapping counters accepted")
	}
	u.Write = n(-1)
	if _, err = u.tokens(); err == nil {
		t.Fatal("negative accepted")
	}
	u.Write = n(0)
	u.Reasoning = n(21)
	if _, err = u.tokens(); err == nil {
		t.Fatal("reasoning counted outside output")
	}
}

func TestCodexScopeBoundariesAndDedup(t *testing.T) {
	raw := `{"type":"session_meta","payload":{"id":"s","model_provider":"openai"}}
{"type":"turn_context","payload":{"model":"gpt-6-astra"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"a","name":"exec_command"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"b","name":"mcp__test"}}
{"timestamp":"2026-09-17T10:00:00Z","type":"token_usage_record","payload":{"thread_id":"s","response_id":"r1","usage":{"input_tokens":10,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":2}}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"a"}}
{"type":"response_item","payload":{"type":"function_call_output","call_id":"b"}}
{"type":"token_usage_record","payload":{"thread_id":"s","response_id":"r1","usage":{"input_tokens":10}}}
{"type":"response_item","payload":{"type":"message","role":"assistant"}}
{"timestamp":"2026-09-17T10:00:01Z","type":"token_usage_record","payload":{"thread_id":"s","response_id":"r2","usage":{"input_tokens":20,"cached_input_tokens":10,"cache_write_input_tokens":0,"output_tokens":3}}}
{"type":"event_msg","payload":{"type":"task_started"}}
{"type":"response_item","payload":{"type":"message","role":"user"}}
{"type":"response_item","payload":{"type":"message","role":"assistant"}}
{"timestamp":"2026-09-17T10:00:02Z","type":"token_usage_record","payload":{"thread_id":"s","response_id":"r3","usage":{"input_tokens":30,"cached_input_tokens":10,"cache_write_input_tokens":0,"output_tokens":4}}}
`
	rows, err := ReadCodexTranscript(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || len(rows[0].ToolUseIDs) != 2 || len(rows[1].ConsumedToolUseIDs) != 2 || len(rows[1].Tools) != 2 {
		t.Fatalf("scope: %+v", rows)
	}
	// Repeat the entire file to exercise resume/re-read idempotence.
	rows, err = ReadCodexTranscript(strings.NewReader(raw + raw))
	if err != nil || len(rows) != 2 {
		t.Fatalf("duplicate: %d %v", len(rows), err)
	}
}

func TestCodexLegacyUsageFailsClosed(t *testing.T) {
	_, err := ReadCodexTranscript(strings.NewReader(`{"type":"session_meta","payload":{"id":"s","model_provider":"openai"}}` + "\n" + `{"type":"event_msg","payload":{"type":"token_count"}}`))
	if err == nil {
		t.Fatal("legacy cumulative-only format silently accepted")
	}
}
