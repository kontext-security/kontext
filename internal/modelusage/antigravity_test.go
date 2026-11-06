package modelusage

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

const antigravityTestSession = "antigravity-2163ba71-0862-48c7-87c8-197903c4cacb"

// testdata/antigravity-tool-turn.jsonl keeps the row order, tool calls and token
// counts of a real Antigravity 2.29.0 run, with parallel tool calls in one model
// response, and has its prompt and output text removed.
//
// Ways the parser can fail, each pinned below:
//   - a call's id differs from the one its hooks report, so cost never joins the
//     ledger's tool calls (a parallel call's step is the response's plus its place)
//   - cached input is counted twice: input_tokens already excludes it
//   - the transcript names no model, so records go out without one, or a later
//     model switch rewrites what earlier responses cost
//   - a system message or a sub-agent's first row counts as a person's prompt
//   - prompt, argument or output text leaks into a record
//   - an incremental read disagrees with a full read
func TestAntigravityTranscriptRecords(t *testing.T) {
	t.Parallel()
	transcript := NewAntigravityTranscript(antigravityTestSession)
	transcript.SetModel("gemini-3.5-flash-lite")
	records, err := transcript.Read(bytes.NewReader(readAntigravityTranscript(t)))
	if err != nil {
		t.Fatal(err)
	}
	const id = "agy-2163ba71-0862-48c7-87c8-197903c4cacb-"
	want := []struct {
		message            string
		uses, consumed     []string
		tools              []string
		input, cached, out int64
	}{
		{"step-1", []string{id + "2", id + "3"}, nil, []string{"Read", "Bash"}, 10382, 0, 296},
		{"step-4", []string{id + "5"}, []string{id + "2", id + "3"}, []string{"Read", "Read", "Bash"}, 2750, 8100, 218},
		{"step-6", nil, []string{id + "5"}, []string{"Read"}, 3057, 8096, 33},
		{"step-8", []string{id + "9"}, nil, []string{"Bash"}, 3209, 8111, 92},
		{"step-10", nil, []string{id + "9"}, []string{"Bash"}, 3396, 8105, 6},
		{"step-11", []string{id + "12"}, nil, []string{"mcp__spikelazy__echo_tool"}, 3094, 10114, 62},
		{"step-13", nil, []string{id + "12"}, []string{"mcp__spikelazy__echo_tool"}, 3396, 8105, 6},
	}
	if len(records) != len(want) {
		t.Fatalf("records = %d, want %d: %+v", len(records), len(want), records)
	}
	for i, w := range want {
		r := records[i]
		if r.SessionID != antigravityTestSession || r.MessageID != w.message || r.RequestID != w.message || r.Model != "gemini-3.5-flash-lite" {
			t.Errorf("%s: identity %q %q %q %q", w.message, r.SessionID, r.MessageID, r.RequestID, r.Model)
		}
		if !slices.Equal(r.ToolUseIDs, w.uses) || !slices.Equal(r.ConsumedToolUseIDs, w.consumed) {
			t.Errorf("%s: uses %v consumed %v, want %v %v", w.message, r.ToolUseIDs, r.ConsumedToolUseIDs, w.uses, w.consumed)
		}
		var names []string
		for _, tool := range r.Tools {
			names = append(names, tool.Name)
		}
		if !slices.Equal(names, w.tools) {
			t.Errorf("%s: tools %v, want %v", w.message, names, w.tools)
		}
		if *r.Tokens.InputUncached != w.input || *r.Tokens.InputCacheRead != w.cached || *r.Tokens.Output != w.out {
			t.Errorf("%s: tokens %d %d %d", w.message, *r.Tokens.InputUncached, *r.Tokens.InputCacheRead, *r.Tokens.Output)
		}
		if *r.Tokens.InputCacheWrite != 0 || *r.Tokens.CacheWrite5m != 0 || *r.Tokens.CacheWrite1h != 0 {
			t.Errorf("%s: an unknown write bucket leaves the request unpriced", w.message)
		}
		if r.Timestamp == "" || !r.ToolRelated() {
			t.Errorf("%s: timestamp %q related %v", w.message, r.Timestamp, r.ToolRelated())
		}
	}
	mcp := records[5].Tools[0]
	if mcp.ServerName != "spikelazy" || mcp.ID != id+"12" {
		t.Fatalf("mcp tool = %+v", mcp)
	}
	raw, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"text removed", "Fix the failing", "does-not-exist", "removed"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("records carry %q: %s", leak, raw)
		}
	}
}

func TestAntigravityTranscriptPromptsAreThePersonsOnly(t *testing.T) {
	t.Parallel()
	transcript := NewAntigravityTranscript(antigravityTestSession)
	transcript.SetModel("m")
	if _, err := transcript.Read(bytes.NewReader(readAntigravityTranscript(t))); err != nil {
		t.Fatal(err)
	}
	prompts := transcript.Prompts()
	if len(prompts) != 1 || prompts[0].SessionID != antigravityTestSession || prompts[0].Timestamp.IsZero() {
		t.Fatalf("prompts = %+v; the SYSTEM_MESSAGE at step 7 is not a prompt", prompts)
	}
}

func TestAntigravityTranscriptWithholdsRecordsUntilItKnowsTheModel(t *testing.T) {
	t.Parallel()
	raw := readAntigravityTranscript(t)
	transcript := NewAntigravityTranscript(antigravityTestSession)
	records, err := transcript.Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 {
		t.Fatalf("records without a model went out: %+v", records)
	}
	transcript.SetModel("gemini-3.5-flash-lite")
	records, err = transcript.Read(bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 7 || records[0].Model != "gemini-3.5-flash-lite" {
		t.Fatalf("records = %+v", records)
	}
}

func TestAntigravityTranscriptKeepsEachResponsesModel(t *testing.T) {
	t.Parallel()
	lines := bytes.SplitAfter(readAntigravityTranscript(t), []byte("\n"))
	transcript := NewAntigravityTranscript(antigravityTestSession)
	transcript.SetModel("first-model")
	if _, err := transcript.Read(bytes.NewReader(bytes.Join(lines[:2], nil))); err != nil {
		t.Fatal(err)
	}
	transcript.SetModel("second-model")
	records, err := transcript.Read(bytes.NewReader(bytes.Join(lines[2:], nil)))
	if err != nil {
		t.Fatal(err)
	}
	if records[0].Model != "first-model" || records[1].Model != "second-model" {
		t.Fatalf("models = %q %q", records[0].Model, records[1].Model)
	}
}

// The app's default model reports as gemini-3.8-flash-tiered. Left as is, it
// matches no published price and all its usage stays unpriced.
func TestAntigravityTranscriptRecordsThePublishedModelID(t *testing.T) {
	t.Parallel()
	for reported, want := range map[string]string{
		"gemini-3.8-flash-tiered":     "gemini-3.8-flash",
		"gemini-3.5-flash-lite":       "gemini-3.5-flash-lite",
		"gemini-3.1-flash-lite":       "gemini-3.1-flash-lite",
		"gemini-4-argon-high":         "gemini-4-argon",
		"gemini-3.5-flash-extra-low":  "gemini-3.5-flash",
		"gemini-3.1-pro-low-thinking": "gemini-3.1-pro",
		"claude-opus-5-5-max":         "claude-opus-5-5",
		"auto":                        "auto",
	} {
		transcript := NewAntigravityTranscript(antigravityTestSession)
		transcript.SetModel(reported)
		records, err := transcript.Read(bytes.NewReader(readAntigravityTranscript(t)))
		if err != nil {
			t.Fatal(err)
		}
		if records[0].Model != want {
			t.Errorf("%s recorded as %s, want %s", reported, records[0].Model, want)
		}
	}
}

func TestAntigravityTranscriptIncrementalReadMatchesFullRead(t *testing.T) {
	t.Parallel()
	raw := readAntigravityTranscript(t)
	full := NewAntigravityTranscript(antigravityTestSession)
	full.SetModel("m")
	want, err := full.Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut < len(raw); cut += 97 {
		transcript := NewAntigravityTranscript(antigravityTestSession)
		transcript.SetModel("m")
		if _, err := transcript.Read(bytes.NewReader(raw[:cut])); err != nil {
			continue // a line cut in half is not valid yet
		}
		got, err := transcript.Read(bytes.NewReader(raw[transcript.Offset():]))
		if err != nil {
			t.Fatalf("cut %d: %v", cut, err)
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		if !bytes.Equal(gotJSON, wantJSON) {
			t.Fatalf("cut %d differs:\n%s\n%s", cut, gotJSON, wantJSON)
		}
	}
}

func TestAntigravityTranscriptRejectsImpossibleCounts(t *testing.T) {
	t.Parallel()
	row := `{"type":"PLANNER_RESPONSE","step_index":1,"created_at":"2026-11-06T15:36:05Z","input_tokens":-1,"output_tokens":1,"cache_read_tokens":0,"tool_calls":[{"name":"run_command","args":{}}]}` + "\n"
	transcript := NewAntigravityTranscript(antigravityTestSession)
	transcript.SetModel("m")
	if _, err := transcript.Read(strings.NewReader(row)); err == nil {
		t.Fatal("want an error for a negative count")
	}
}

func readAntigravityTranscript(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/antigravity-tool-turn.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
