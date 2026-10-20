package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
)

func testTurn(id, session string, startedAt time.Time, prompt TurnPrompt) TurnRecord {
	return TurnRecord{Schema: TurnSchemaVersion, ID: id, SessionID: session, Agent: "claude",
		StartedAt: FormatTurnTime(startedAt), Source: TurnSourceUserPrompt, Prompt: prompt}
}

func TestTurnOutboxSequenceAndWireShape(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	for _, turn := range []TurnRecord{
		testTurn("turn_a", "s", base, ExcerptTurnPrompt(`fix the "cost" <summary>`, 25, false, strings.Repeat("a", 64))),
		testTurn("turn_other", "other", base.Add(time.Second), SizeOnlyTurnPrompt(TurnPromptOmitted, 9)),
		testTurn("turn_b", "s", base.Add(2*time.Second), SizeOnlyTurnPrompt(TurnPromptSkipped, 12)),
		// A resent id never takes a second sequence.
		testTurn("turn_a", "s", base.Add(3*time.Second), SizeOnlyTurnPrompt(TurnPromptSkipped, 1)),
	} {
		if err := store.SaveTurn(ctx, turn); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := store.PendingTurns(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	want := `[` +
		`{"schema":"turn/v1","id":"turn_a","session_id":"s","sequence":1,"agent":"claude","started_at":"2026-10-19T10:00:00.000000000Z","source":"user_prompt","prompt":{"mode":"excerpt","text":"fix the \"cost\" ` + "\\u003csummary\\u003e" + `","chars":25,"truncated":false,"sha256":"` + strings.Repeat("a", 64) + `"}},` +
		`{"schema":"turn/v1","id":"turn_other","session_id":"other","sequence":1,"agent":"claude","started_at":"2026-10-19T10:00:01.000000000Z","source":"user_prompt","prompt":{"mode":"omitted","chars":9}},` +
		`{"schema":"turn/v1","id":"turn_b","session_id":"s","sequence":2,"agent":"claude","started_at":"2026-10-19T10:00:02.000000000Z","source":"user_prompt","prompt":{"mode":"skipped","chars":12}}` +
		`]`
	if string(encoded) != want {
		t.Fatalf("pending turns =\n%s\nwant\n%s", encoded, want)
	}
	if err := store.AcknowledgeTurns(ctx, []string{"turn_a", "turn_other"}); err != nil {
		t.Fatal(err)
	}
	pending, err = store.PendingTurns(ctx, 50)
	if err != nil || len(pending) != 1 || pending[0].ID != "turn_b" {
		t.Fatalf("after ack: %+v, %v", pending, err)
	}
	if pending, err := store.PendingTurns(ctx, 0); err != nil || len(pending) != 0 {
		t.Fatalf("limit 0: %+v, %v", pending, err)
	}
	if err := store.SaveTurn(ctx, TurnRecord{ID: "turn_x", SessionID: "s", StartedAt: FormatTurnTime(base), Prompt: TurnPrompt{Mode: TurnPromptExcerpt}}); err == nil {
		t.Fatal("an excerpt without text was stored")
	}
}

// A restarted daemon resolves an event's turn from SQLite by the event's own
// time, so a deferred write that runs late still finds the right turn.
func TestCurrentTurnAt(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	for _, turn := range []TurnRecord{
		testTurn("turn_1", "s", base, SizeOnlyTurnPrompt(TurnPromptSkipped, 1)),
		testTurn("turn_2", "s", base.Add(10*time.Second), SizeOnlyTurnPrompt(TurnPromptSkipped, 1)),
	} {
		if err := store.SaveTurn(ctx, turn); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		at   time.Time
		want string
	}{
		{base.Add(-time.Second), ""},
		{base, "turn_1"},
		{base.Add(9 * time.Second), "turn_1"},
		{base.Add(10 * time.Second), "turn_2"},
		{base.Add(time.Hour), "turn_2"},
	} {
		got, err := store.CurrentTurn(ctx, "s", test.at)
		if err != nil || got != test.want {
			t.Errorf("CurrentTurn(%v) = %q, %v; want %q", test.at, got, err, test.want)
		}
	}
	if got, err := store.CurrentTurn(ctx, "other", base.Add(time.Hour)); err != nil || got != "" {
		t.Errorf("other session = %q, %v", got, err)
	}
}

// Exported turns are pruned only past the revisit window of every transcript
// of their session: the reader stamps a session's usage again on each read.
func TestPruneExportedTurnsWaitsForTheRevisitWindow(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	old := now.Add(-8 * 24 * time.Hour)
	for _, turn := range []TurnRecord{
		testTurn("turn_live", "live", old, SizeOnlyTurnPrompt(TurnPromptSkipped, 1)),
		testTurn("turn_done", "done", old, SizeOnlyTurnPrompt(TurnPromptSkipped, 1)),
		testTurn("turn_unsent", "done", old.Add(time.Second), SizeOnlyTurnPrompt(TurnPromptSkipped, 1)),
		testTurn("turn_recent", "done", now.Add(-time.Hour), SizeOnlyTurnPrompt(TurnPromptSkipped, 1)),
		testTurn("turn_unread", "unread", old, SizeOnlyTurnPrompt(TurnPromptSkipped, 1)),
	} {
		if err := store.SaveTurn(ctx, turn); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.AcknowledgeTurns(ctx, []string{"turn_live", "turn_done", "turn_recent", "turn_unread"}); err != nil {
		t.Fatal(err)
	}
	// "live" still has a transcript within the revisit window; "done" has one
	// last seen long ago; "unread" one never read successfully.
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "live", Agent: "claude", HookName: hook.HookStop, TranscriptPath: filepath.Join(dir, "live.jsonl")}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`insert into tool_usage_sources(session_id, transcript_path, agent, last_seen, fingerprint) values
 ('done', ?, 'claude', ?, 'tool-metadata-v4:1:1'), ('unread', ?, 'claude', ?, '')`,
		filepath.Join(dir, "done.jsonl"), old.Format(time.RFC3339Nano), filepath.Join(dir, "unread.jsonl"), old.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	for _, session := range []string{"live", "done"} {
		if _, err := store.db.Exec(`insert into tool_usage_prompts(session_id, started_at) values(?, ?)`, session, FormatTurnTime(old)); err != nil {
			t.Fatal(err)
		}
	}
	pruned, err := store.PruneExportedTurns(ctx, now.Add(-UsageRevisitWindow), 100)
	if err != nil || pruned != 1 {
		t.Fatalf("pruned = %d, %v; want only turn_done", pruned, err)
	}
	var left []string
	rows, err := store.db.Query(`select id from turns order by id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		left = append(left, id)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(left, ",") != "turn_live,turn_recent,turn_unread,turn_unsent" {
		t.Fatalf("kept turns = %v", left)
	}
	var prompts []string
	rows, err = store.db.Query(`select session_id from tool_usage_prompts order by session_id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var session string
		if err := rows.Scan(&session); err != nil {
			t.Fatal(err)
		}
		prompts = append(prompts, session)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(prompts, ",") != "live" {
		t.Fatalf("kept prompts = %v", prompts)
	}
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(strings.Join(lines, "\n") + "\n")
	if err := errors.Join(err, f.Close()); err != nil {
		t.Fatal(err)
	}
}

func claudePromptLine(ts, text string) string {
	return fmt.Sprintf(`{"type":"user","sessionId":"s","timestamp":"%s","message":{"role":"user","content":%q}}`, ts, text)
}

func claudeToolLines(ts, message, tool string, sidechain bool) []string {
	flag := ""
	if sidechain {
		flag = `,"isSidechain":true`
	}
	return []string{
		fmt.Sprintf(`{"type":"assistant","sessionId":"s","timestamp":"%s"%s,"message":{"id":"%s","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"%s","name":"Bash"}],"usage":{"output_tokens":5}}}`, ts, flag, message, tool),
		fmt.Sprintf(`{"type":"user","sessionId":"s","timestamp":"%s"%s,"message":{"content":[{"type":"tool_result","tool_use_id":"%s","content":"ok"}]}}`, ts, flag, tool),
	}
}

func pendingTurnIDs(t *testing.T, store *Store) map[string]string {
	t.Helper()
	page, err := store.PendingToolUsage(context.Background(), 100)
	if err != nil {
		t.Fatal(err)
	}
	turns := map[string]string{}
	for _, record := range page {
		turns[record.MessageID] = record.TurnID
	}
	return turns
}

// The reader stamps usage with minted turns across a subagent transcript,
// a daemon restart, and a turn minted after its usage was first read.
func TestReconcileStampsUsageWithMintedTurns(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "guard.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close() }()
	parent := filepath.Join(dir, "s.jsonl")
	agent := filepath.Join(dir, "s", "subagents", "agent-a.jsonl")
	if err := os.MkdirAll(filepath.Dir(agent), 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		transcriptCursors.take(transcriptKey{path: parent})
		transcriptCursors.take(transcriptKey{path: agent})
	})
	base := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	ts := func(offset time.Duration) string { return base.Add(offset).Format(time.RFC3339Nano) }
	mint := func(id string, offset time.Duration) {
		t.Helper()
		if err := store.SaveTurn(ctx, testTurn(id, "s", base.Add(offset), SizeOnlyTurnPrompt(TurnPromptSkipped, 3))); err != nil {
			t.Fatal(err)
		}
	}
	reconcile := func() {
		t.Helper()
		if err := store.ReconcileToolUsage(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// A session resumed from before the install: its first prompt has no
	// minted turn and keeps its usage unstamped.
	appendLines(t, parent, claudePromptLine(ts(-time.Hour), "earlier"))
	appendLines(t, parent, claudeToolLines(ts(-time.Hour+time.Second), "m0", "t0", false)...)
	appendLines(t, parent, claudePromptLine(ts(0), "run printf once"))
	appendLines(t, parent, claudeToolLines(ts(time.Second), "m1", "t1", false)...)
	mint("turn_1", 20*time.Millisecond)
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: parent}); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if got := pendingTurnIDs(t, store); got["m0"] != "" || got["m1"] != "turn_1" {
		t.Fatalf("first pass turns = %v", got)
	}

	// The subagent's own file, registered at SubagentStop and first read in
	// the same pass as the parent's next prompt, falls into the parent turn
	// it ran under; its task row is no prompt.
	appendLines(t, agent, `{"type":"user","sessionId":"s","timestamp":"`+ts(2*time.Second)+`","isSidechain":true,"message":{"role":"user","content":"Explore and report."}}`)
	appendLines(t, agent, claudeToolLines(ts(3*time.Second), "m1s", "t1s", true)...)
	appendLines(t, parent, claudePromptLine(ts(10*time.Second), "now explain"))
	appendLines(t, parent, claudeToolLines(ts(11*time.Second), "m2", "t2", false)...)
	mint("turn_2", 10*time.Second+30*time.Millisecond)
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookSubagentStop, TranscriptPath: parent, AgentTranscriptPath: agent}); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if got := pendingTurnIDs(t, store); got["m1s"] != "turn_1" || got["m2"] != "turn_2" {
		t.Fatalf("subagent pass turns = %v", got)
	}
	page, err := store.PendingToolUsage(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeToolUsage(ctx, page); err != nil {
		t.Fatal(err)
	}

	// A daemon restart loses parser state; the turns and the session's
	// boundaries are in SQLite, so a full re-read keeps every stamp and
	// re-emits nothing.
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	transcriptCursors.take(transcriptKey{path: parent})
	transcriptCursors.take(transcriptKey{path: agent})
	if store, err = OpenStore(dbPath); err != nil {
		t.Fatal(err)
	}
	// The subagent file alone changes first: its usage is matched against the
	// boundaries stored from the parent, which this pass does not read.
	for _, path := range []string{agent, parent} {
		appendLines(t, path, `{"type":"progress","message":"late"}`)
		reconcile()
		if got := pendingTurnIDs(t, store); len(got) != 0 {
			t.Fatalf("restart re-emitted usage after %s changed: %v", filepath.Base(path), got)
		}
	}

	// Usage read before its turn's deferred write lands carries no turn, and
	// is re-emitted with it on the next read.
	appendLines(t, parent, claudePromptLine(ts(20*time.Second), "and the tests?"))
	appendLines(t, parent, claudeToolLines(ts(21*time.Second), "m3", "t3", false)...)
	reconcile()
	if got := pendingTurnIDs(t, store); got["m3"] != "" {
		t.Fatalf("usage stamped before its turn existed: %v", got)
	}
	mint("turn_3", 20*time.Second+10*time.Millisecond)
	appendLines(t, parent, `{"type":"progress","message":"later"}`)
	reconcile()
	page, err = store.PendingToolUsage(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || page[0].MessageID != "m3" || page[0].TurnID != "turn_3" {
		t.Fatalf("restamped usage = %+v", page)
	}
}
