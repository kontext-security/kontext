package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/modelusage"
)

func TestToolUsageReconcilesRestartAndAcknowledgesExactRevision(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "session.jsonl")
	first := `{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:44Z","message":{"id":"a","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Bash"}],"usage":{"input_tokens":2,"cache_creation_input_tokens":17270,"cache_read_input_tokens":34745,"output_tokens":83,"cache_creation":{"ephemeral_1h_input_tokens":17270,"ephemeral_5m_input_tokens":0}}}}` + "\n"
	result := `{"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"t","content":"ok"}]}}` + "\n"
	last := `{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:45Z","message":{"id":"b","model":"claude-fable-5-1","usage":{"input_tokens":32,"cache_creation_input_tokens":121,"cache_read_input_tokens":52015,"output_tokens":4,"cache_creation":{"ephemeral_1h_input_tokens":121,"ephemeral_5m_input_tokens":0}}}}` + "\n"
	unrelated := `{"type":"user","sessionId":"s","message":{"content":"hello"}}` + "\n" + `{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:46Z","message":{"id":"c","model":"claude-fable-5-1","usage":{"output_tokens":25}}}` + "\n"
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(first+result+last[:30]), 0600); err != nil {
		t.Fatal(err)
	}
	event := hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: path}
	if err := store.TrackToolTranscript(ctx, event); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	page, err := store.PendingToolUsage(ctx, 50)
	if err != nil || len(page) != 1 {
		t.Fatalf("initial page: %+v, %v", page, err)
	}
	if err := store.AcknowledgeToolUsage(ctx, page); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := os.WriteFile(path, []byte(first+result+last+unrelated), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	page, err = store.PendingToolUsage(ctx, 50)
	if err != nil || len(page) != 1 || page[0].MessageID != "b" {
		t.Fatalf("restart must recover final tool-result response only: %+v %v", page, err)
	}
	if len(page[0].ConsumedToolUseIDs) != 1 || page[0].Tools[0].Name != "Bash" {
		t.Fatalf("missing result link: %+v", page)
	}
	old := page[0]
	newOutput := int64(8)
	page[0].Tokens.Output = &newOutput
	if err := store.SaveToolUsage(ctx, "claude", page[0].Record); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeToolUsage(ctx, []ToolUsageRecord{old}); err != nil {
		t.Fatal(err)
	}
	page, err = store.PendingToolUsage(ctx, 50)
	if err != nil || len(page) != 1 || *page[0].Tokens.Output != 8 || page[0].Revision <= old.Revision {
		t.Fatalf("old ack lost new snapshot: %+v %v", page, err)
	}
	if err := store.AcknowledgeToolUsage(ctx, page); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	page, err = store.PendingToolUsage(ctx, 50)
	if err != nil || len(page) != 0 {
		t.Fatalf("unchanged source must not reupload: %+v %v", page, err)
	}
}

func TestCodexToolUsageReconciliation(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	path, err := filepath.Abs("../../../modelusage/testdata/codex-tool-turn.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	event := hook.Event{SessionID: "codex-01a0afe3-75c0-73e1-81ef-233317e1fb2c", Agent: "codex", HookName: hook.HookStop, TranscriptPath: path}
	for i := 0; i < 2; i++ {
		if err := store.TrackToolTranscript(ctx, event); err != nil {
			t.Fatal(err)
		}
		if err := store.ReconcileToolUsage(ctx); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := store.PendingToolUsage(ctx, 50)
	if err != nil || len(rows) != 2 {
		t.Fatalf("codex records: %+v %v", rows, err)
	}
	if rows[0].Agent != "codex" || rows[0].SessionID != event.SessionID {
		t.Fatalf("identity: %+v", rows[0])
	}
	if err := store.AcknowledgeToolUsage(ctx, rows); err != nil {
		t.Fatal(err)
	}
	// Simulate the previous collector: old metadata and an unchanged transcript.
	oldRevision := rows[1].Revision
	for _, row := range rows {
		for i := range row.Tools {
			row.Tools[i].Type = ""
		}
		payload, err := json.Marshal(row.Record)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, `update tool_usage_records set payload=? where revision=?`, string(payload), row.Revision); err != nil {
			t.Fatal(err)
		}
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `update tool_usage_sources set fingerprint=?`, fmt.Sprintf("tool-metadata-v2:%d:%d", stat.Size(), stat.ModTime().UnixNano())); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err = store.PendingToolUsage(ctx, 50)
	if err != nil || len(rows) != 2 || rows[0].Revision <= oldRevision || rows[0].Tools[0].Type == "" {
		t.Fatalf("metadata upgrade must replace existing usage: %+v %v", rows, err)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `select count(*) from tool_usage_records`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("metadata refresh duplicated usage: %d %v", count, err)
	}
	if err := store.AcknowledgeToolUsage(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err = store.PendingToolUsage(ctx, 50)
	if err != nil || len(rows) != 0 {
		t.Fatalf("reuploaded: %+v %v", rows, err)
	}
}

func TestToolUsageKeepsProviderSessionsSeparate(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// Even identical raw session/message IDs belong to distinct sessions after
	// adapter normalization. Exercise both parsers rather than inventing IDs.
	claude, err := modelusage.ReadClaudeTranscript(strings.NewReader(`{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:44Z","message":{"id":"m","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Bash"}],"usage":{"output_tokens":10}}}` + "\n"))
	if err != nil || len(claude) != 1 {
		t.Fatalf("claude records: %+v %v", claude, err)
	}
	codex, err := modelusage.ReadCodexTranscript(strings.NewReader(`{"type":"session_meta","payload":{"id":"s","model_provider":"openai"}}
{"type":"turn_context","payload":{"model":"gpt-6-astra"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"t","name":"exec_command"}}
{"timestamp":"2026-09-16T13:36:44Z","type":"token_usage_record","payload":{"thread_id":"s","response_id":"m","usage":{"input_tokens":20,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":30}}}
`))
	if err != nil || len(codex) != 1 {
		t.Fatalf("codex records: %+v %v", codex, err)
	}
	if err := store.SaveToolUsage(ctx, "claude", claude[0]); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveToolUsage(ctx, "codex", codex[0]); err != nil {
		t.Fatal(err)
	}
	rows, err := store.PendingToolUsage(ctx, 50)
	if err != nil || len(rows) != 2 {
		t.Fatalf("one provider replaced another: %+v %v", rows, err)
	}
	if rows[0].Agent != "claude" || rows[0].SessionID != "s" || *rows[0].Tokens.Output != 10 ||
		rows[1].Agent != "codex" || rows[1].SessionID != "codex-s" || *rows[1].Tokens.Output != 30 {
		t.Fatalf("provider identity or usage changed: %+v", rows)
	}
}

func TestToolUsageAgentCorrectionDoesNotDuplicateRequest(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record := modelusage.Record{SessionID: "s", MessageID: "m", ToolUseIDs: []string{"t"}}
	if err := store.SaveToolUsage(ctx, "claude", record); err != nil {
		t.Fatal(err)
	}
	old, err := store.PendingToolUsage(ctx, 50)
	if err != nil || len(old) != 1 {
		t.Fatalf("initial request: %+v %v", old, err)
	}
	// A corrected agent label must replace the snapshot under the same cloud
	// identity. An upload of the previous label may still be in flight.
	if err := store.SaveToolUsage(ctx, "cowork", record); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeToolUsage(ctx, old); err != nil {
		t.Fatal(err)
	}
	updated, err := store.PendingToolUsage(ctx, 50)
	if err != nil || len(updated) != 1 || updated[0].Agent != "cowork" || updated[0].Revision <= old[0].Revision {
		t.Fatalf("agent correction must remain pending: %+v %v", updated, err)
	}
	if err := store.SaveToolUsage(ctx, "cowork", record); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeToolUsage(ctx, updated); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingToolUsage(ctx, 50)
	if err != nil || len(pending) != 0 {
		t.Fatalf("unchanged correction created a new revision: %+v %v", pending, err)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `select count(*) from tool_usage_records`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("agent correction duplicated the request: %d %v", count, err)
	}
}

func totalChanges(t *testing.T, store *Store) int64 {
	t.Helper()
	var changes int64
	if err := store.db.QueryRow(`select total_changes()`).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	return changes
}

func TestToolUsageUnchangedPassWritesNothing(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	path := filepath.Join(dir, "session.jsonl")
	line := `{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:44Z","message":{"id":"m","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Bash"}],"usage":{"output_tokens":10}}}` + "\n"
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: path}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	before := totalChanges(t, store)
	for i := 0; i < 3; i++ {
		if err := store.ReconcileToolUsage(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if after := totalChanges(t, store); after != before {
		t.Fatalf("unchanged transcript rewrote %d rows", after-before)
	}
	// A change is still picked up on the next pass.
	if err := os.WriteFile(path, []byte(line+`{"type":"user","sessionId":"s","message":{"content":"hello"}}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if after := totalChanges(t, store); after == before {
		t.Fatal("changed transcript was not re-read")
	}
}

func TestToolUsageRetiresMissingTranscripts(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	for _, src := range []struct{ path, lastSeen string }{
		// Gone for longer than the grace period.
		{filepath.Join(dir, "gone.jsonl"), now.Add(-2 * time.Hour).Format(time.RFC3339Nano)},
		// Never read successfully and outside the seven-day window: the old
		// fingerprint='' clause re-selected these on every pass forever.
		{filepath.Join(dir, "stuck.jsonl"), now.Add(-30 * 24 * time.Hour).Format(time.RFC3339Nano)},
		// Just registered; the file may not be flushed yet.
		{filepath.Join(dir, "fresh.jsonl"), now.Format(time.RFC3339Nano)},
	} {
		if _, err := store.db.ExecContext(ctx, `insert into tool_usage_sources(session_id, transcript_path, agent, last_seen) values('s', ?, 'claude', ?)`, src.path, src.lastSeen); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	var path, message string
	if err := store.db.QueryRowContext(ctx, `select transcript_path, error from tool_usage_sources`).Scan(&path, &message); err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "fresh.jsonl" || !strings.Contains(message, "no such file") {
		t.Fatalf("only the fresh source should remain, with its error: %s %q", path, message)
	}
	before := totalChanges(t, store)
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if after := totalChanges(t, store); after != before {
		t.Fatalf("repeating the same error rewrote %d rows", after-before)
	}
	// A live session re-registers a retired source on its next hook.
	gone := filepath.Join(dir, "gone.jsonl")
	if err := os.WriteFile(gone, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookStop, TranscriptPath: gone}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	var fingerprint string
	if err := store.db.QueryRowContext(ctx, `select fingerprint from tool_usage_sources where transcript_path=?`, gone).Scan(&fingerprint); err != nil || fingerprint == "" {
		t.Fatalf("re-registered source was not read: %q %v", fingerprint, err)
	}
}

func TestToolUsageReadLimitDoesNotStarveChangedSources(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	line := `{"type":"user","sessionId":"s","message":{"content":"hello"}}` + "\n"
	var paths []string
	for i := 0; i <= toolUsageReadLimit; i++ {
		path := filepath.Join(dir, fmt.Sprintf("session-%03d.jsonl", i))
		if err := os.WriteFile(path, []byte(line), 0600); err != nil {
			t.Fatal(err)
		}
		if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: path}); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	unread := func() []string {
		rows, err := store.db.QueryContext(ctx, `select transcript_path from tool_usage_sources where fingerprint = ''`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var result []string
		for rows.Next() {
			var path string
			if err := rows.Scan(&path); err != nil {
				t.Fatal(err)
			}
			result = append(result, path)
		}
		return result
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if left := unread(); len(left) != 1 {
		t.Fatalf("first pass must stop at the read limit: %d unread", len(left))
	}
	// Every source that was read changes again; the one still waiting must
	// go first rather than lose to sources read a moment ago.
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(line+line), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if left := unread(); len(left) != 0 {
		t.Fatalf("changed source starved: %v", left)
	}
}

func TestToolUsageFailedReadWaitsForChange(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	path := filepath.Join(dir, "session.jsonl")
	// A tool-related message without a timestamp fails the whole read.
	bad := `{"type":"assistant","sessionId":"s","message":{"id":"m","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Bash"}],"usage":{"output_tokens":10}}}` + "\n"
	if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: path}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	before := totalChanges(t, store)
	for i := 0; i < 3; i++ {
		if err := store.ReconcileToolUsage(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if after := totalChanges(t, store); after != before {
		t.Fatalf("unchanged failing transcript rewrote %d rows", after-before)
	}
	good := `{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:44Z","message":{"id":"m","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Bash"}],"usage":{"output_tokens":10}}}` + "\n"
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	// Keep the change visible even on filesystems with coarse mtimes.
	future := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	var fingerprint, message string
	if err := store.db.QueryRowContext(ctx, `select fingerprint, error from tool_usage_sources`).Scan(&fingerprint, &message); err != nil || fingerprint == "" || message != "" {
		t.Fatalf("fixed transcript not re-read: fingerprint %q error %q err %v", fingerprint, message, err)
	}
}

func TestToolUsageRetireKeepsFreshRegistration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	path := filepath.Join(dir, "session.jsonl")
	stale := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	if _, err := store.db.ExecContext(ctx, `insert into tool_usage_sources(session_id, transcript_path, agent, last_seen) values('s', ?, 'claude', ?)`, path, stale); err != nil {
		t.Fatal(err)
	}
	sources, err := store.toolUsageSources(ctx, time.Now().UTC())
	if err != nil || len(sources) != 1 {
		t.Fatalf("sources %+v %v", sources, err)
	}
	// A hook re-registers the source between the snapshot and the delete.
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookStop, TranscriptPath: path}); err != nil {
		t.Fatal(err)
	}
	if err := store.applyToolUsageUpdates(ctx, []toolUsageUpdate{{source: sources[0], retire: true}}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `select count(*) from tool_usage_sources`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("fresh registration deleted: %d %v", count, err)
	}
}
