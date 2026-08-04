package managedstream

// Throwaway replay harness: drains a copy of a real wedged guard.db against a
// fake ingest server. Run manually:
//   KONTEXT_REPLAY_DB=/path/guard-copy.db KONTEXT_REPLAY_CURSOR=2026-07-12T10:04:31.732097Z \
//   KONTEXT_REPLAY_ACTION_ID=act_9d3adf32-230e-471a-85f9-31f74a8bbb39 \
//   go test ./internal/managedstream -run TestReplayLiveDB -v -timeout 30m

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
)

func TestReplayLiveDB(t *testing.T) {
	dbPath := os.Getenv("KONTEXT_REPLAY_DB")
	if dbPath == "" {
		t.Skip("KONTEXT_REPLAY_DB not set")
	}
	var batches, actions, receipts, sessions int
	var bytesTotal int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		bytesTotal += int64(len(body))
		var p wireBatch
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("bad payload: %v", err)
		}
		batches++
		actions += len(p.Actions)
		receipts += len(p.Receipts)
		sessions += len(p.Sessions)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	cursor, err := time.Parse(time.RFC3339Nano, os.Getenv("KONTEXT_REPLAY_CURSOR"))
	if err != nil {
		t.Fatalf("parse cursor: %v", err)
	}
	if err := SaveState(statePath, State{UpdatedAfter: &cursor, ActionID: os.Getenv("KONTEXT_REPLAY_ACTION_ID")}); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	flushErr := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "replay-install",
		InstallToken:   "replay-token",
		Diagnostic:     diagnostic.New(os.Stderr, true),
	})
	elapsed := time.Since(start)

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("flush err: %v", flushErr)
	t.Logf("elapsed: %s, batches: %d, actions: %d, receipts: %d, sessions: %d, bytes: %.1f MB",
		elapsed, batches, actions, receipts, sessions, float64(bytesTotal)/1024/1024)
	if state.UpdatedAfter != nil {
		t.Logf("final cursor: %s (id %s)", state.UpdatedAfter.Format(time.RFC3339Nano), state.ActionID)
	} else {
		t.Log("final cursor: nil")
	}
	if state.UpdatedAfter == nil || !state.UpdatedAfter.After(cursor) {
		t.Fatal("cursor did not advance past the wedged position")
	}
}
