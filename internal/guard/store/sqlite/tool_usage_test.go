package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
