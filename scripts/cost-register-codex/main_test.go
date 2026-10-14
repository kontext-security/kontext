package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
)

func TestRegisterPreservesIdentityAndReconcilesWithoutHookEvents(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "guard.db")
	path, err := filepath.Abs("../../internal/modelusage/testdata/codex-tool-turn.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	session := "01a0afe3-75c0-73e1-81ef-233317e1fb2c"
	if err := register(db, path, "other-session"); err == nil {
		t.Fatal("accepted different session")
	}
	if _, err := os.Stat(db); !os.IsNotExist(err) {
		t.Fatal("identity rejection should not touch database")
	}
	for i := 0; i < 2; i++ {
		if err := register(db, path, session); err != nil {
			t.Fatal(err)
		}
	}
	store, err := sqlite.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := store.PendingToolUsage(ctx, 50)
	if err != nil || len(rows) != 2 {
		t.Fatalf("records = %d, error = %v", len(rows), err)
	}
	sessions, err := store.AgentSessions(ctx, []string{"codex-" + session})
	if err != nil || len(sessions) != 1 {
		t.Fatalf("owning session missing: %v", err)
	}
	if err := store.AcknowledgeToolUsage(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err = store.PendingToolUsage(ctx, 50)
	if err != nil || len(rows) != 0 {
		t.Fatalf("duplicate upload: %d, %v", len(rows), err)
	}
}

func TestRegisterSubagentUnderItsRootSession(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "guard.db")
	path := filepath.Join(dir, "rollout-child.jsonl")
	rollout := `{"type":"session_meta","payload":{"id":"child","session_id":"root","forked_from_id":"root","parent_thread_id":"root","thread_source":"subagent","model_provider":"openai","cwd":"/work"}}
{"type":"session_meta","payload":{"id":"root","session_id":"root","model_provider":"openai","cwd":"/work"}}
{"type":"event_msg","payload":{"type":"task_started"}}
{"type":"turn_context","payload":{"model":"gpt-6-astra"}}
{"type":"response_item","payload":{"type":"function_call","call_id":"c","name":"exec_command"}}
{"timestamp":"2026-09-17T10:00:00Z","type":"token_usage_record","payload":{"thread_id":"child","response_id":"r","usage":{"input_tokens":10,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":2}}}
`
	if err := os.WriteFile(path, []byte(rollout), 0600); err != nil {
		t.Fatal(err)
	}
	if err := register(db, path, "child"); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	rows, err := store.PendingToolUsage(ctx, 50)
	if err != nil || len(rows) != 1 || rows[0].SessionID != "codex-root" || rows[0].MessageID != "r" {
		t.Fatalf("records = %+v, error = %v", rows, err)
	}
	sessions, err := store.AgentSessions(ctx, []string{"codex-root"})
	if err != nil || len(sessions) != 1 {
		t.Fatalf("owning session missing: %v", err)
	}
}

func TestRegisterSubagentKeepsRootSessionMetadata(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "guard.db")
	store, err := sqlite.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := store.BackfillObservedSessionWithMode(ctx, "codex-root", "codex", "/root-work", "enforce"); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rollout-child.jsonl")
	rollout := `{"type":"session_meta","payload":{"id":"child","session_id":"root","thread_source":"subagent","model_provider":"openai","cwd":"/child-work"}}` + "\n"
	if err := os.WriteFile(path, []byte(rollout), 0600); err != nil {
		t.Fatal(err)
	}
	if err := register(db, path, "child"); err != nil {
		t.Fatal(err)
	}
	store, err = sqlite.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	root, err := store.Session(ctx, "codex-root")
	if err != nil || root.CWD != "/root-work" || root.Mode != "enforce" {
		t.Fatalf("root session rewritten: %+v, %v", root, err)
	}
}
