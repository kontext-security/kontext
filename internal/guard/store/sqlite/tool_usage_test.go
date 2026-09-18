package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
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
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err = store.PendingToolUsage(ctx, 50)
	if err != nil || len(rows) != 0 {
		t.Fatalf("reuploaded: %+v %v", rows, err)
	}
}
