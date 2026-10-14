package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
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
	failed, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	good := `{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:44Z","message":{"id":"m","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Bash"}],"usage":{"output_tokens":10}}}` + "\n"
	if err := os.WriteFile(path, []byte(good), 0600); err != nil {
		t.Fatal(err)
	}
	// A filesystem with coarse timestamps can keep the failed attempt's
	// mtime; the size change alone must trigger the retry.
	if err := os.Chtimes(path, failed.ModTime(), failed.ModTime()); err != nil {
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

// claudeTurns builds a Claude Code transcript in which each message streams
// as two snapshots and the next message consumes its tool result. Every line
// ends with values derived from base.
func claudeTurns(turns, base int) string {
	var b strings.Builder
	for i := range turns {
		ts := fmt.Sprintf("2026-09-16T13:%02d:%02dZ", i/60, i%60)
		fmt.Fprintf(&b, `{"type":"assistant","sessionId":"s","requestId":"r%d","timestamp":"%s","message":{"id":"m%d","model":"claude-fable-5-1","content":[{"type":"thinking"}],"usage":{"input_tokens":%d,"output_tokens":%d}}}`+"\n", i, ts, i, base+i, base)
		fmt.Fprintf(&b, `{"type":"assistant","sessionId":"s","requestId":"r%d","message":{"id":"m%d","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t%d","name":"Bash"}],"usage":{"output_tokens":%d}}}`+"\n", i, i, i, base+2*i)
		fmt.Fprintf(&b, `{"type":"user","sessionId":"s","message":{"content":[{"type":"tool_result","tool_use_id":"t%d","content":"ok %d"}]}}`+"\n", i, base)
		if i%4 == 3 {
			fmt.Fprintf(&b, `{"type":"progress","message":"step %d %d"}`+"\n", i, base)
		}
	}
	return b.String()
}

func codexTurns(turns, base int) string {
	b := strings.Builder{}
	b.WriteString(`{"type":"session_meta","payload":{"id":"s","model_provider":"openai"}}` + "\n")
	for i := range turns {
		fmt.Fprintf(&b, `{"type":"turn_context","payload":{"model":"gpt-6-astra","service_tier":"tier-%d"}}`+"\n", base)
		fmt.Fprintf(&b, `{"type":"response_item","payload":{"type":"function_call","call_id":"c%d","name":"exec_command","namespace":"ns-%d"}}`+"\n", i, base)
		fmt.Fprintf(&b, `{"timestamp":"2026-09-17T10:%02d:%02dZ","type":"token_usage_record","payload":{"thread_id":"s","response_id":"r%d","usage":{"input_tokens":%d,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":%d}}}`+"\n", i/60, i%60, i, base+i, base)
		fmt.Fprintf(&b, `{"type":"response_item","payload":{"type":"function_call_output","call_id":"c%d","output":"ok %d"}}`+"\n", i, base)
		fmt.Fprintf(&b, `{"type":"event_msg","payload":{"type":"token_count","base":%d}}`+"\n", base)
	}
	return b.String()
}

// codexSubagent builds the rollout of a sub-agent of thread s, shaped like
// Codex 0.154 and later: its own session_meta, whose session_id is s, then a
// copy of the root's history, starting with the root's session_meta, then its
// own turns.
func codexSubagent(rootHistory string, turns, base int) string {
	own := strings.NewReplacer(`"thread_id":"s"`, `"thread_id":"child"`, `"response_id":"r`, `"response_id":"child-r`, `"call_id":"c`, `"call_id":"child-c`).Replace(codexTurns(turns, base))
	_, own, _ = strings.Cut(own, "\n")
	return `{"type":"session_meta","payload":{"id":"child","session_id":"s","forked_from_id":"s","parent_thread_id":"s","thread_source":"subagent","model_provider":"openai"}}` + "\n" +
		rootHistory + `{"type":"event_msg","payload":{"type":"task_started"}}` + "\n" + own
}

func TestToolUsageImportsCodexSubagentRolloutsUnderHookSession(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root := codexTurns(3, 100)
	for name, content := range map[string]string{"root": root, "child": codexSubagent(root, 2, 200)} {
		path := filepath.Join(dir, name+".jsonl")
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
		// Codex reports a sub-agent's hooks under its root thread's session.
		if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "codex-s", Agent: "codex", HookName: hook.HookPostToolUse, TranscriptPath: path}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	var failed int
	if err := store.db.QueryRowContext(ctx, `select count(*) from tool_usage_sources where fingerprint='' or error!=''`).Scan(&failed); err != nil || failed != 0 {
		t.Fatalf("%d sources failed: %v", failed, err)
	}
	rows, err := store.PendingToolUsage(ctx, 50)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, row := range rows {
		if row.SessionID != "codex-s" {
			t.Fatalf("usage outside the hook session: %+v", row)
		}
		got = append(got, row.MessageID)
	}
	// The copied root responses count once, from the root's own rollout.
	slices.Sort(got)
	if want := []string{"child-r0", "child-r1", "r0", "r1", "r2"}; !slices.Equal(got, want) {
		t.Fatalf("records %v, want %v", got, want)
	}
}

// transcriptCopy is one store reading its own copy of a transcript.
type transcriptCopy struct {
	store *Store
	path  string
	key   transcriptKey
}

func (c transcriptCopy) cursor() *modelusage.Transcript {
	transcriptCursors.mu.Lock()
	defer transcriptCursors.mu.Unlock()
	if cursor := transcriptCursors.cursors[c.key]; cursor != nil {
		return cursor.transcript
	}
	return nil
}

func (c transcriptCopy) tables(t *testing.T) string {
	t.Helper()
	return dumpQueries(t, c.store,
		`select revision, session_id, message_id, agent, payload, exported from tool_usage_records order by revision`,
		`select session_id, agent, fingerprint, error from tool_usage_sources`,
	)
}

func dumpQueries(t *testing.T, store *Store, queries ...string) string {
	t.Helper()
	var b strings.Builder
	for _, query := range queries {
		rows, err := store.db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		columns, _ := rows.Columns()
		for rows.Next() {
			values := make([]any, len(columns))
			for i := range values {
				values[i] = new(any)
			}
			if err := rows.Scan(values...); err != nil {
				t.Fatal(err)
			}
			for _, value := range values {
				fmt.Fprintf(&b, "%v|", *value.(*any))
			}
			b.WriteString("\n")
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return b.String()
}

type transcriptChange int

const (
	appendTranscript  transcriptChange = iota
	replaceTranscript                  // a new file renamed over the old one
	rewriteTranscript                  // truncated and refilled in place
)

// TestToolUsageCursorMatchesFullReads feeds the same transcript changes to a
// store that keeps its cursor and to one that reads every transcript in full,
// as before cursors existed. Records, revisions, acknowledgements, and source
// state must stay identical, while appends resume the cursor and every other
// change falls back to a full read.
func TestToolUsageCursorMatchesFullReads(t *testing.T) {
	type step struct {
		change  transcriptChange
		content string
	}
	rng := rand.New(rand.NewSource(1))
	// grow appends to from until it becomes to, cutting lines at random.
	grow := func(from, to string, steps int) []step {
		cuts := make([]int, steps)
		for i := range cuts {
			cuts[i] = len(from) + rng.Intn(len(to)-len(from)+1)
		}
		slices.Sort(cuts)
		var result []step
		for _, cut := range append(cuts, len(to)) {
			result = append(result, step{appendTranscript, to[:cut]})
		}
		return result
	}
	claude, codex := claudeTurns(40, 100), codexTurns(40, 100)
	half := claudeTurns(20, 100)
	badLine := strings.ReplaceAll(strings.SplitAfter(claude, "\n")[0], `"output_tokens":100`, `"output_tokens":-1`)
	for _, scenario := range []struct {
		name, agent, session string
		steps                []step
	}{
		{"claude appends", "claude", "s", grow("", claude, 12)},
		{"codex appends", "codex", "codex-s", grow("", codex, 12)},
		{"codex sub-agent appends", "codex", "codex-s", grow("", codexSubagent(codexTurns(20, 100), 20, 200), 12)},
		{"claude replaced, rewritten, and truncated", "claude", "s", slices.Concat(
			grow("", half, 3),
			// A new file that differs only before the parsed tail.
			[]step{{replaceTranscript, strings.Replace(claudeTurns(25, 100), `"input_tokens":100,`, `"input_tokens":199,`, 1)}},
			[]step{{replaceTranscript, claudeTurns(30, 200)}},
			grow(claudeTurns(30, 200), claudeTurns(35, 200), 2),
			[]step{{rewriteTranscript, claudeTurns(40, 300)}},
			[]step{{rewriteTranscript, claudeTurns(10, 300)}},
			grow(claudeTurns(10, 300), claudeTurns(20, 300), 2),
		)},
		{"claude failing line", "claude", "s", slices.Concat(
			grow("", half, 3),
			grow(half, half+badLine+claude, 4),
		)},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			ctx := context.Background()
			var copies [2]transcriptCopy
			for i := range copies {
				dir := t.TempDir()
				store, err := OpenStore(filepath.Join(dir, "guard.db"))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { store.Close() })
				path := filepath.Join(dir, "session.jsonl")
				copies[i] = transcriptCopy{store: store, path: path, key: transcriptKey{codex: scenario.agent == "codex", path: path}}
				t.Cleanup(func() { transcriptCursors.take(copies[i].key) })
			}
			incremental, full := copies[0], copies[1]
			written := ""
			resumed := 0
			for n, step := range scenario.steps {
				// One mtime per step keeps both copies' fingerprints equal.
				modTime := time.Unix(1_800_000_000+int64(n), 0)
				for _, c := range copies {
					var err error
					switch {
					case step.change == replaceTranscript:
						if err = os.WriteFile(c.path+".tmp", []byte(step.content), 0600); err == nil {
							err = os.Rename(c.path+".tmp", c.path)
						}
					case step.change == appendTranscript && strings.HasPrefix(step.content, written):
						var f *os.File
						if f, err = os.OpenFile(c.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err == nil {
							_, err = f.WriteString(step.content[len(written):])
							err = errors.Join(err, f.Close())
						}
					default:
						err = os.WriteFile(c.path, []byte(step.content), 0600)
					}
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Chtimes(c.path, modTime, modTime); err != nil {
						t.Fatal(err)
					}
					if err := c.store.TrackToolTranscript(ctx, hook.Event{SessionID: scenario.session, Agent: scenario.agent, HookName: hook.HookPostToolUse, TranscriptPath: c.path}); err != nil {
						t.Fatal(err)
					}
				}
				written = step.content
				before := incremental.cursor()
				transcriptCursors.take(full.key)
				for _, c := range copies {
					if err := c.store.ReconcileToolUsage(ctx); err != nil {
						t.Fatal(err)
					}
				}
				after := incremental.cursor()
				if want := before != nil && step.change == appendTranscript; (before == after) != want {
					t.Fatalf("step %d (%v): cursor resumed %v, want %v", n, step.change, before == after, want)
				}
				if before == after {
					resumed++
				}
				if offset := after.Offset(); offset != int64(strings.LastIndexByte(step.content, '\n')+1) && !strings.Contains(scenario.name, "failing") {
					t.Fatalf("step %d: offset %d is not the end of the last complete line", n, offset)
				}
				if got, want := incremental.tables(t), full.tables(t); got != want {
					t.Fatalf("step %d (%v): cursor diverged from full reads:\n got %s\nwant %s", n, step.change, got, want)
				}
				// Upload and acknowledge on alternate steps, as an outage would.
				if n%2 == 0 {
					var pages [2][]ToolUsageRecord
					for i, c := range copies {
						page, err := c.store.PendingToolUsage(ctx, 50)
						if err != nil {
							t.Fatal(err)
						}
						if err := c.store.AcknowledgeToolUsage(ctx, page); err != nil {
							t.Fatal(err)
						}
						pages[i] = page
					}
					if !reflect.DeepEqual(pages[0], pages[1]) {
						t.Fatalf("step %d: uploads diverged:\n got %+v\nwant %+v", n, pages[0], pages[1])
					}
				}
			}
			if resumed == 0 {
				t.Fatal("no pass resumed a cursor")
			}
			var message string
			if err := incremental.store.db.QueryRow(`select error from tool_usage_sources`).Scan(&message); err != nil {
				t.Fatal(err)
			}
			if failing := strings.Contains(scenario.name, "failing"); failing != strings.Contains(message, "negative token count") || !failing && message != "" {
				t.Fatalf("source error %q", message)
			}
		})
	}
}

func TestToolUsageCursorEvictsIdleTranscripts(t *testing.T) {
	now := time.Now()
	idle, active := transcriptKey{path: t.TempDir() + "/idle.jsonl"}, transcriptKey{path: t.TempDir() + "/active.jsonl"}
	transcriptCursors.put(idle, &transcriptCursor{used: now.Add(-transcriptCursorIdle - time.Second)})
	transcriptCursors.put(active, &transcriptCursor{used: now.Add(-time.Second)})
	transcriptCursors.evict(now)
	if transcriptCursors.take(idle) != nil || transcriptCursors.take(active) == nil {
		t.Fatal("only the idle transcript's parser state should be dropped")
	}
}

// countRecordWrites reopens store's connection through one that counts the
// statements writing tool_usage_records, including those that change no row.
func countRecordWrites(t *testing.T, store *Store) *atomic.Int64 {
	t.Helper()
	writes := new(atomic.Int64)
	connector := countingConnector{driver: store.db.Driver(), dsn: store.path, writes: writes}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	store.db = sql.OpenDB(connector)
	store.db.SetMaxOpenConns(1)
	if _, err := store.db.Exec("pragma busy_timeout = 5000"); err != nil {
		t.Fatal(err)
	}
	return writes
}

type countingConnector struct {
	driver driver.Driver
	dsn    string
	writes *atomic.Int64
}

func (c countingConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.driver.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return countingConn{conn.(sqliteConn), c.writes}, nil
}

func (c countingConnector) Driver() driver.Driver { return c.driver }

type sqliteConn interface {
	driver.Conn
	driver.ConnBeginTx
	driver.ExecerContext
	driver.QueryerContext
}

type countingConn struct {
	sqliteConn
	writes *atomic.Int64
}

func (c countingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.HasPrefix(query, "insert or replace into tool_usage_records") {
		c.writes.Add(1)
	}
	return c.sqliteConn.ExecContext(ctx, query, args)
}

// applyEveryToolUsageRecord is applyToolUsageUpdates as it was before it
// skipped unchanged records: one statement per record, then the source row.
func applyEveryToolUsageRecord(ctx context.Context, s *Store, updates []toolUsageUpdate, now time.Time) error {
	if len(updates) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, update := range updates {
		src := update.source
		if update.retire {
			if _, err := tx.ExecContext(ctx, `delete from tool_usage_sources where session_id=? and transcript_path=? and last_seen=?`, src.session, src.path, src.lastSeen); err != nil {
				return err
			}
			continue
		}
		for _, record := range update.records {
			if err := saveToolUsage(ctx, tx, src.agent, record); err != nil {
				return err
			}
		}
		if update.read {
			_, err = tx.ExecContext(ctx, `update tool_usage_sources set checked_at=?, fingerprint=?, error=?, error_fingerprint=? where session_id=? and transcript_path=?`,
				now.Format(time.RFC3339Nano), update.fingerprint, update.message, update.errorFingerprint, src.session, src.path)
		} else {
			_, err = tx.ExecContext(ctx, `update tool_usage_sources set error=?, error_fingerprint='' where session_id=? and transcript_path=?`,
				update.message, src.session, src.path)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TestToolUsageSkippingUnchangedRecordsMatchesSavingAll applies the same
// passes with and without skipping unchanged records. Two transcripts share a
// session and its message IDs, agents get corrected, a pass may carry a
// message twice, and uploads are acknowledged while later passes replace
// their revisions. Records, revisions, and acknowledgements must stay
// identical, and every skipped statement must be one that would have changed
// nothing.
func TestToolUsageSkippingUnchangedRecordsMatchesSavingAll(t *testing.T) {
	ctx := context.Background()
	var stores [2]*Store
	for i := range stores {
		store, err := OpenStore(filepath.Join(t.TempDir(), "guard.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { store.Close() })
		stores[i] = store
	}
	skipping, saving := stores[0], stores[1]
	writes := countRecordWrites(t, skipping)
	sources := []toolUsageSource{
		{session: "s", path: "/p/main.jsonl", agent: "claude"},
		{session: "s", path: "/p/subagent.jsonl", agent: "claude"},
		{session: "codex-s", path: "/p/rollout.jsonl", agent: "codex"},
	}
	// Each transcript's messages and their current output tokens. A read
	// returns all of them, as every pass does.
	transcripts := make([]map[string]int64, len(sources))
	for i := range transcripts {
		transcripts[i] = map[string]int64{}
	}
	record := func(session, message string, output int64) modelusage.Record {
		return modelusage.Record{SessionID: session, MessageID: message, Timestamp: "2026-09-16T13:36:44Z",
			ToolUseIDs: []string{"t-" + message}, Tokens: modelusage.Tokens{Output: &output}}
	}
	queries := []string{
		`select revision, session_id, message_id, agent, payload, exported from tool_usage_records order by revision`,
		`select seq from sqlite_sequence where name='tool_usage_records'`,
	}
	rng := rand.New(rand.NewSource(1))
	var inFlight [2][]ToolUsageRecord
	uploading, offered, foreign := false, 0, 0
	for pass := range 500 {
		var updates []toolUsageUpdate
		for i, src := range sources {
			switch rng.Intn(10) {
			case 0, 1:
				continue // unchanged transcript
			case 2:
				updates = append(updates, toolUsageUpdate{source: src, message: "stat failed"})
				continue
			case 3:
				updates = append(updates, toolUsageUpdate{source: src, retire: true})
				continue
			}
			if rng.Intn(5) == 0 {
				src.agent = "cowork"
			}
			transcripts[i][fmt.Sprintf("m%d", rng.Intn(8))] = int64(rng.Intn(3))
			update := toolUsageUpdate{source: src, read: true, fingerprint: fmt.Sprint(pass)}
			for _, message := range slices.Sorted(maps.Keys(transcripts[i])) {
				update.records = append(update.records, record(src.session, message, transcripts[i][message]))
			}
			if rng.Intn(10) == 0 {
				twice := update.records[rng.Intn(len(update.records))]
				update.records = append(update.records, record(twice.SessionID, twice.MessageID, *twice.Tokens.Output+1))
			}
			if rng.Intn(10) == 0 {
				update.records = append(update.records, record("other", "m0", int64(rng.Intn(3))))
				foreign++
			}
			if rng.Intn(10) == 0 {
				update.records = append(update.records, modelusage.Record{SessionID: src.session, MessageID: "m0"})
			}
			for _, record := range update.records {
				if record.ToolRelated() {
					offered++
				}
			}
			updates = append(updates, update)
		}
		rng.Shuffle(len(updates), func(i, j int) { updates[i], updates[j] = updates[j], updates[i] })
		if !uploading && rng.Intn(2) == 0 {
			limit := 1 + rng.Intn(10)
			for i, store := range stores {
				page, err := store.PendingToolUsage(ctx, limit)
				if err != nil {
					t.Fatal(err)
				}
				inFlight[i] = page
			}
			if !reflect.DeepEqual(inFlight[0], inFlight[1]) {
				t.Fatalf("pass %d: uploads diverged:\n got %+v\nwant %+v", pass, inFlight[0], inFlight[1])
			}
			uploading = true
		}
		now := time.Unix(1_800_000_000+int64(pass), 0).UTC()
		if err := skipping.applyToolUsageUpdates(ctx, updates, now); err != nil {
			t.Fatal(err)
		}
		if err := applyEveryToolUsageRecord(ctx, saving, updates, now); err != nil {
			t.Fatal(err)
		}
		if uploading && rng.Intn(2) == 0 {
			for i, store := range stores {
				if err := store.AcknowledgeToolUsage(ctx, inFlight[i]); err != nil {
					t.Fatal(err)
				}
			}
			uploading = false
		}
		if got, want := dumpQueries(t, skipping, queries...), dumpQueries(t, saving, queries...); got != want {
			t.Fatalf("pass %d: tables diverged:\n got %s\nwant %s", pass, got, want)
		}
	}
	var revisions int64
	if err := skipping.db.QueryRow(queries[1]).Scan(&revisions); err != nil {
		t.Fatal(err)
	}
	// A statement that changes nothing is issued only for a record of
	// another session, which reconcile passes never carry.
	if writes.Load() < revisions || writes.Load() > revisions+int64(foreign) || revisions >= int64(offered) {
		t.Fatalf("%d statements for %d revisions out of %d records, %d of another session", writes.Load(), revisions, offered, foreign)
	}
}

func TestToolUsageUnchangedRecordsIssueNoStatements(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	writes := countRecordWrites(t, store)
	path := filepath.Join(dir, "session.jsonl")
	t.Cleanup(func() { transcriptCursors.take(transcriptKey{path: path}) })
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: path}); err != nil {
		t.Fatal(err)
	}
	var revision int64
	for n, appended := range []string{
		claudeTurns(40, 100),
		// Re-read without changing any record.
		`{"type":"progress","message":"still working"}` + "\n",
		claudeTurns(41, 100)[len(claudeTurns(40, 100)):],
	} {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.WriteString(appended)
		if err := errors.Join(err, f.Close()); err != nil {
			t.Fatal(err)
		}
		writes.Store(0)
		before := totalChanges(t, store)
		if err := store.ReconcileToolUsage(ctx); err != nil {
			t.Fatal(err)
		}
		changes := totalChanges(t, store) - before
		var revised int64
		if err := store.db.QueryRow(`select count(*), coalesce(max(revision), ?) from tool_usage_records where revision > ?`, revision, revision).Scan(&revised, &revision); err != nil {
			t.Fatal(err)
		}
		// Every statement allocates a revision, and only the unchanged pass
		// allocates none: it writes the source row and nothing else.
		if writes.Load() != revised || (revised == 0) != (n == 1) || n == 1 && changes != 1 {
			t.Fatalf("pass %d: %d record statements, %d new revisions, %d row changes", n, writes.Load(), revised, changes)
		}
	}
}

// A pass that reads stored records must still wait for another connection's
// write lock. If its transaction read before writing, SQLite would refuse the
// upgrade to a write with SQLITE_BUSY at once, without busy_timeout.
func TestToolUsageReconcileWaitsForAnotherWriter(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	var stores [2]*Store
	for i := range stores {
		store, err := OpenStore(filepath.Join(dir, "guard.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		stores[i] = store
	}
	store, other := stores[0], stores[1]
	path := filepath.Join(dir, "session.jsonl")
	t.Cleanup(func() { transcriptCursors.take(transcriptKey{path: path}) })
	if err := os.WriteFile(path, []byte(claudeTurns(3, 100)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: path}); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(claudeTurns(4, 100)), 0600); err != nil {
		t.Fatal(err)
	}
	tx, err := other.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `update tool_usage_sources set last_seen=last_seen`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- store.ReconcileToolUsage(ctx) }()
	select {
	case err := <-done:
		t.Fatalf("pass ended while another connection held the write lock: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// A Codex sub-agent started without its parent's history has one session_meta
// whose session_id names the root. The previous adapter labeled its records
// with the sub-agent's own id, so they were dropped, yet the read succeeded
// and its fingerprint was saved. The adapter version in the fingerprint makes
// such a source read once more.
func TestToolUsageRereadsSourcesReadByThePreviousAdapter(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	path := filepath.Join(dir, "rollout-child.jsonl")
	rollout := `{"type":"session_meta","payload":{"id":"child","session_id":"root","thread_source":"subagent","model_provider":"openai"}}
{"type":"turn_context","payload":{"model":"gpt-6-astra"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"c","name":"exec_command"}}
{"timestamp":"2026-09-17T10:00:00Z","type":"token_usage_record","payload":{"thread_id":"child","response_id":"r","usage":{"input_tokens":10,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":2}}}
`
	if err := os.WriteFile(path, []byte(rollout), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "codex-root", Agent: "codex", HookName: hook.HookStop, TranscriptPath: path}); err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `update tool_usage_sources set fingerprint=?, checked_at=?`,
		fmt.Sprintf("tool-metadata-v3:%d:%d", stat.Size(), stat.ModTime().UnixNano()), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := store.PendingToolUsage(ctx, 50)
	if err != nil || len(rows) != 1 || rows[0].SessionID != "codex-root" {
		t.Fatalf("records = %+v, error = %v", rows, err)
	}
}
