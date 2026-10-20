package modelusage

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func at(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func turnsByMessage(records []Record) map[string]string {
	turns := map[string]string{}
	for _, record := range records {
		turns[record.MessageID] = record.TurnID
	}
	return turns
}

// The golden transcript holds a session resumed from before the install (its
// first prompt has no minted turn), a prompt whose turn runs a subagent
// interleaved as sidechain rows and is auto-compacted mid-turn, a prompt
// absorbed mid-turn, and a last prompt two seconds after that one.
func TestClaudeTranscriptTurns(t *testing.T) {
	data, err := os.ReadFile("testdata/claude-turns.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	transcript := NewClaudeTranscript()
	records, err := transcript.Read(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	var prompts []time.Time
	for _, prompt := range transcript.Prompts() {
		if prompt.SessionID != "s" {
			t.Fatalf("prompt session = %q", prompt.SessionID)
		}
		prompts = append(prompts, prompt.Timestamp)
	}
	// Meta, sidechain and compact-summary user rows start no turn; the
	// absorbed queued prompt does.
	want := []time.Time{at(t, "2026-10-19T09:00:00Z"), at(t, "2026-10-19T10:00:00Z"), at(t, "2026-10-19T10:00:08.5Z"), at(t, "2026-10-19T10:00:10.5Z")}
	if len(prompts) != len(want) {
		t.Fatalf("prompts = %v, want %v", prompts, want)
	}
	for i := range want {
		if !prompts[i].Equal(want[i]) {
			t.Fatalf("prompt %d = %v, want %v", i, prompts[i], want[i])
		}
	}

	// Hooks as the daemon received them: none before the install, then within
	// a few hundred milliseconds of each prompt line, in either order.
	AssignTurns(records, prompts, []Turn{
		{ID: "turn_typed", StartedAt: at(t, "2026-10-19T10:00:00.020Z")},
		{ID: "turn_absorbed", StartedAt: at(t, "2026-10-19T10:00:08.495Z")},
		{ID: "turn_explain", StartedAt: at(t, "2026-10-19T10:00:10.530Z")},
	})
	got := turnsByMessage(records)
	for message, turn := range map[string]string{
		"m0": "", "m0b": "", // resumed prefix
		"m1": "turn_typed", "m1s": "turn_typed", "m2": "turn_typed", "m3": "turn_typed",
		"m4": "turn_absorbed",
		"m5": "turn_explain", "m6": "turn_explain",
	} {
		if got[message] != turn {
			t.Errorf("%s turn = %q, want %q (all: %v)", message, got[message], turn, got)
		}
	}
}

// A prompt whose hook was missed must not take the next prompt's turn, and
// its records stay unmatched rather than inheriting a label.
func TestMissedHookDoesNotStealTheNextTurn(t *testing.T) {
	records := []Record{
		{MessageID: "first", Timestamp: "2026-10-19T10:00:05Z"},
		{MessageID: "second", Timestamp: "2026-10-19T10:00:25Z"},
	}
	AssignTurns(records,
		[]time.Time{at(t, "2026-10-19T10:00:00Z"), at(t, "2026-10-19T10:00:20Z")},
		[]Turn{{ID: "turn_second", StartedAt: at(t, "2026-10-19T10:00:20Z")}})
	if records[0].TurnID != "" || records[1].TurnID != "turn_second" {
		t.Fatalf("turns = %v", turnsByMessage(records))
	}
}

func TestAssignTurnsIntervals(t *testing.T) {
	prompts := []time.Time{at(t, "2026-10-19T10:00:00Z"), at(t, "2026-10-19T10:00:02Z")}
	record := func(ts string) []Record { return []Record{{MessageID: "m", Timestamp: ts}} }
	for _, test := range []struct {
		name    string
		turns   []Turn
		records []Record
		want    string
	}{
		{name: "hook just before the line", turns: []Turn{{ID: "a", StartedAt: at(t, "2026-10-19T09:59:59.4Z")}}, records: record("2026-10-19T10:00:01Z"), want: "a"},
		{name: "hook more than the skew before belongs to no prompt", turns: []Turn{{ID: "a", StartedAt: at(t, "2026-10-19T09:59:58.9Z")}}, records: record("2026-10-19T10:00:01Z"), want: ""},
		{name: "codex hook seconds after task_started", turns: []Turn{{ID: "b", StartedAt: at(t, "2026-10-19T10:00:02.9Z")}}, records: record("2026-10-19T10:00:03Z"), want: "b"},
		{name: "earliest of two turns wins", turns: []Turn{{ID: "late", StartedAt: at(t, "2026-10-19T10:00:00.5Z")}, {ID: "early", StartedAt: at(t, "2026-10-19T10:00:00.1Z")}}, records: record("2026-10-19T10:00:01Z"), want: "early"},
		{name: "second prompt's hook does not belong to the first", turns: []Turn{{ID: "b", StartedAt: at(t, "2026-10-19T10:00:01.5Z")}}, records: record("2026-10-19T10:00:01Z"), want: ""},
		{name: "record before the first prompt", turns: []Turn{{ID: "a", StartedAt: at(t, "2026-10-19T10:00:00Z")}}, records: record("2026-10-19T09:59:59Z"), want: ""},
		{name: "unparseable timestamp", turns: []Turn{{ID: "a", StartedAt: at(t, "2026-10-19T10:00:00Z")}}, records: []Record{{MessageID: "m", Timestamp: "", TurnID: "stale"}}, want: ""},
		{name: "no prompts clears a stale stamp", records: []Record{{MessageID: "m", Timestamp: "2026-10-19T10:00:01Z", TurnID: "stale"}}, want: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := prompts
			if test.name == "no prompts clears a stale stamp" {
				p = nil
			}
			AssignTurns(test.records, p, test.turns)
			if got := test.records[0].TurnID; got != test.want {
				t.Fatalf("turn = %q, want %q", got, test.want)
			}
		})
	}
}

// Reading the transcript line by line returns the same boundaries as one
// full read, including an unterminated last line.
func TestClaudePromptsIncremental(t *testing.T) {
	data, err := os.ReadFile("testdata/claude-turns.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	full := NewClaudeTranscript()
	if _, err := full.Read(strings.NewReader(string(data))); err != nil {
		t.Fatal(err)
	}
	incremental := NewClaudeTranscript()
	text := strings.TrimSuffix(string(data), "\n")
	for offset := 0; offset < len(text); {
		end := min(offset+97, len(text))
		if _, err := incremental.Read(strings.NewReader(text[incremental.Offset():end])); err != nil {
			t.Fatal(err)
		}
		offset = end
	}
	if got, want := incremental.Prompts(), full.Prompts(); len(got) != len(want) {
		t.Fatalf("incremental prompts = %v, want %v", got, want)
	}
}

func TestCodexTranscriptTurns(t *testing.T) {
	rollout := func(lines ...string) string { return strings.Join(lines, "\n") + "\n" }
	usage := func(ts, thread, response string) string {
		return `{"timestamp":"` + ts + `","type":"token_usage_record","payload":{"thread_id":"` + thread + `","response_id":"` + response + `","usage":{"input_tokens":10,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":2,"reasoning_output_tokens":0}}}`
	}
	call := func(ts, id string) string {
		return `{"timestamp":"` + ts + `","type":"response_item","payload":{"type":"function_call","call_id":"` + id + `","name":"exec_command"}}`
	}
	main := rollout(
		`{"timestamp":"2026-10-19T10:00:00Z","type":"session_meta","payload":{"id":"th","model_provider":"openai"}}`,
		`{"timestamp":"2026-10-19T10:00:00Z","type":"turn_context","payload":{"model":"gpt-5.6-luna"}}`,
		`{"timestamp":"2026-10-19T10:00:00.100Z","type":"event_msg","payload":{"type":"task_started"}}`,
		`{"timestamp":"2026-10-19T10:00:00.200Z","type":"response_item","payload":{"type":"message","role":"user"}}`,
		`{"timestamp":"2026-10-19T10:00:00.300Z","type":"response_item","payload":{"type":"message","role":"user"}}`,
		call("2026-10-19T10:00:01Z", "c1"),
		usage("2026-10-19T10:00:01.100Z", "th", "resp1"),
		`{"timestamp":"2026-10-19T10:00:02Z","type":"event_msg","payload":{"type":"task_complete"}}`,
		// A task without a user message, e.g. a review, is its own boundary.
		`{"timestamp":"2026-10-19T10:01:00Z","type":"event_msg","payload":{"type":"task_started"}}`,
		call("2026-10-19T10:01:01Z", "c2"),
		usage("2026-10-19T10:01:01.100Z", "th", "resp2"),
		// A user message after model output in the same task steers it: a new turn.
		`{"timestamp":"2026-10-19T10:01:05Z","type":"response_item","payload":{"type":"message","role":"user"}}`,
		call("2026-10-19T10:01:06Z", "c3"),
		usage("2026-10-19T10:01:06.100Z", "th", "resp3"),
	)
	transcript := NewCodexTranscript()
	records, err := transcript.Read(strings.NewReader(main))
	if err != nil || len(records) != 3 {
		t.Fatalf("records = %+v, %v", records, err)
	}
	prompts := transcript.Prompts()
	if len(prompts) != 3 || prompts[0].SessionID != "codex-th" ||
		!prompts[0].Timestamp.Equal(at(t, "2026-10-19T10:00:00.1Z")) ||
		!prompts[1].Timestamp.Equal(at(t, "2026-10-19T10:01:00Z")) ||
		!prompts[2].Timestamp.Equal(at(t, "2026-10-19T10:01:05Z")) {
		t.Fatalf("prompts = %+v", prompts)
	}

	// A sub-agent rollout copies its parent's history under the copy's
	// timestamp and runs tasks the parent gave it: no boundaries of its own.
	sub := rollout(
		`{"timestamp":"2026-10-19T10:00:30Z","type":"session_meta","payload":{"id":"child","session_id":"th","model_provider":"openai"}}`,
		`{"timestamp":"2026-10-19T10:00:30Z","type":"session_meta","payload":{"id":"th","model_provider":"openai"}}`,
		`{"timestamp":"2026-10-19T10:00:30Z","type":"event_msg","payload":{"type":"task_started"}}`,
		`{"timestamp":"2026-10-19T10:00:30Z","type":"response_item","payload":{"type":"message","role":"user"}}`,
		`{"timestamp":"2026-10-19T10:00:30Z","type":"turn_context","payload":{"model":"gpt-5.6-luna"}}`,
		`{"timestamp":"2026-10-19T10:00:30.100Z","type":"event_msg","payload":{"type":"task_started"}}`,
		call("2026-10-19T10:00:31Z", "s1"),
		usage("2026-10-19T10:00:31.100Z", "child", "resp-sub"),
	)
	child := NewCodexTranscript()
	subRecords, err := child.Read(strings.NewReader(sub))
	if err != nil || len(subRecords) != 1 || subRecords[0].SessionID != "codex-th" {
		t.Fatalf("sub-agent records = %+v, %v", subRecords, err)
	}
	if got := child.Prompts(); len(got) != 0 {
		t.Fatalf("sub-agent prompts = %+v, want none", got)
	}

	// Matched against the root session's prompts, the sub-agent's usage
	// lands in the root turn it ran under.
	var times []time.Time
	for _, prompt := range prompts {
		times = append(times, prompt.Timestamp)
	}
	turns := []Turn{{ID: "turn_1", StartedAt: at(t, "2026-10-19T10:00:01.2Z")}, {ID: "turn_3", StartedAt: at(t, "2026-10-19T10:01:05.1Z")}}
	AssignTurns(records, times, turns)
	AssignTurns(subRecords, times, turns)
	got := turnsByMessage(append(records, subRecords...))
	// The hook for the first prompt fired 1.1 s after task_started, inside
	// that prompt's interval; the review task minted none.
	for message, turn := range map[string]string{"resp1": "turn_1", "resp-sub": "turn_1", "resp2": "", "resp3": "turn_3"} {
		if got[message] != turn {
			t.Errorf("%s turn = %q, want %q", message, got[message], turn)
		}
	}
}

func TestClaudeRowsThatStartNoTurn(t *testing.T) {
	transcript := NewClaudeTranscript()
	_, err := transcript.Read(strings.NewReader(strings.Join([]string{
		`{"type":"user","sessionId":"s","timestamp":"2026-10-19T10:00:00Z","message":{"content":[{"type":"tool_result"}]}}`,
		`{"type":"user","sessionId":"s","timestamp":"2026-10-19T10:00:01Z","message":{"content":""}}`,
		`{"type":"user","sessionId":"s","timestamp":"not a time","message":{"content":"typed"}}`,
		`{"type":"queue-operation","operation":"enqueue","sessionId":"s","timestamp":"2026-10-19T10:00:02Z"}`,
		`{"type":"queue-operation","operation":"remove","sessionId":"s","timestamp":"2026-10-19T10:00:03Z"}`,
		`{"type":"user","sessionId":"s","timestamp":"2026-10-19T10:00:04Z","message":{"content":[{"type":"image"}]}}`,
	}, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Only the image-only prompt starts a turn: a dequeued prompt is written as
	// its own user row, and a row without a valid time cannot be placed.
	if prompts := transcript.Prompts(); len(prompts) != 1 || !prompts[0].Timestamp.Equal(at(t, "2026-10-19T10:00:04Z")) {
		t.Fatalf("prompts = %+v", prompts)
	}
}

// Harness messages delivered as prompts start no turn: a task notification
// mid-turn (as a user row and as an absorbed queued message) and a session
// event after the turn ended. The usage after them keeps the person's turn.
// A prompt that only begins with a reminder block still starts one.
func TestClaudeHarnessMessagesStartNoTurn(t *testing.T) {
	data, err := os.ReadFile("testdata/claude-envelopes.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	transcript := NewClaudeTranscript()
	records, err := transcript.Read(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	var prompts []time.Time
	for _, prompt := range transcript.Prompts() {
		prompts = append(prompts, prompt.Timestamp)
	}
	if len(prompts) != 2 || !prompts[0].Equal(at(t, "2026-10-20T10:00:00Z")) || !prompts[1].Equal(at(t, "2026-10-20T10:00:30Z")) {
		t.Fatalf("prompts = %v, want the two typed prompts", prompts)
	}
	// The daemon minted turns for the two typed prompts only.
	AssignTurns(records, prompts, []Turn{
		{ID: "turn_background", StartedAt: at(t, "2026-10-20T10:00:00.020Z")},
		{ID: "turn_fix", StartedAt: at(t, "2026-10-20T10:00:30.020Z")},
	})
	got := turnsByMessage(records)
	for message, turn := range map[string]string{
		"m1": "turn_background", "m2": "turn_background", "m3": "turn_background", "m4": "turn_background",
		"m5": "turn_background", // after the session event, which minted nothing
		"m6": "turn_fix", "m7": "turn_fix",
	} {
		if got[message] != turn {
			t.Errorf("%s turn = %q, want %q (all: %v)", message, got[message], turn, got)
		}
	}
}

// Codex writes injected context as user messages, mid-task too; it starts no
// turn, while a person's message after model output does.
func TestCodexInjectedContextStartsNoTurn(t *testing.T) {
	message := func(ts, text string) string {
		return `{"timestamp":"` + ts + `","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":` + strconv.Quote(text) + `}]}}`
	}
	rollout := strings.Join([]string{
		`{"timestamp":"2026-10-20T10:00:00Z","type":"session_meta","payload":{"id":"th","model_provider":"openai"}}`,
		`{"timestamp":"2026-10-20T10:00:00Z","type":"turn_context","payload":{"model":"gpt-5.6-luna"}}`,
		`{"timestamp":"2026-10-20T10:00:00.100Z","type":"event_msg","payload":{"type":"task_started"}}`,
		message("2026-10-20T10:00:00.200Z", "fix the spec"),
		`{"timestamp":"2026-10-20T10:00:01Z","type":"response_item","payload":{"type":"function_call","call_id":"c1","name":"exec_command"}}`,
		message("2026-10-20T10:00:02Z", `<external_codex_apps_open_page>{"page_id":null}</external_codex_apps_open_page>`),
		message("2026-10-20T10:00:02.100Z", "<environment_context>\n  <cwd>/tmp</cwd>\n</environment_context>"),
		`{"timestamp":"2026-10-20T10:00:03Z","type":"response_item","payload":{"type":"function_call","call_id":"c2","name":"exec_command"}}`,
		message("2026-10-20T10:00:04Z", "also update the docs"),
		`{"timestamp":"2026-10-20T10:00:05Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_image","image_url":"data:"}]}}`,
	}, "\n") + "\n"
	transcript := NewCodexTranscript()
	if _, err := transcript.Read(strings.NewReader(rollout)); err != nil {
		t.Fatal(err)
	}
	var got []time.Time
	for _, prompt := range transcript.Prompts() {
		got = append(got, prompt.Timestamp)
	}
	want := []time.Time{at(t, "2026-10-20T10:00:00.1Z"), at(t, "2026-10-20T10:00:04Z")}
	if len(got) != len(want) || !got[0].Equal(want[0]) || !got[1].Equal(want[1]) {
		t.Fatalf("prompts = %v, want %v (the image-only message joins the open turn)", got, want)
	}
}
