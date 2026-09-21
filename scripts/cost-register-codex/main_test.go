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
