package managedstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/modelusage"
)

func TestFlushCapturesUsageBeforeFailedNetworkRequest(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "guard.db")
	transcript := filepath.Join(dir, "session.jsonl")
	data := `{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:44Z","message":{"id":"a","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Bash"}],"usage":{"output_tokens":83}}}`
	if err := os.WriteFile(transcript, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.EnsureObservedSessionWithMode(ctx, "s", "claude", dir, "observe"); err != nil {
		t.Fatal(err)
	}
	if err := store.TrackToolTranscript(ctx, hook.Event{SessionID: "s", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: transcript}); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	if err := Flush(ctx, Options{DBPath: path, CloudURL: server.URL, InstallationID: "ins_test", InstallToken: "test"}); err == nil {
		t.Fatal("expected network failure")
	}
	rows, err := store.PendingToolUsage(ctx, 50)
	if err != nil || len(rows) != 1 {
		t.Fatalf("usage must already be durable offline: %+v, %v", rows, err)
	}
}

func TestToolUsageUploadRetriesWithoutDroppingRecords(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "guard.db")
	store, err := sqlite.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.EnsureObservedSessionWithMode(ctx, "s", "claude", "/tmp", "observe"); err != nil {
		t.Fatal(err)
	}
	records, err := modelusage.ReadClaudeTranscript(strings.NewReader(`{"type":"assistant","sessionId":"s","timestamp":"2026-09-16T13:36:44Z","message":{"id":"a","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Bash"}],"usage":{"output_tokens":83}}}` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveToolUsage(ctx, "claude", records[0]); err != nil {
		t.Fatal(err)
	}
	reject := true
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		if len(p.ToolUsage) != 1 || len(p.Sessions) != 1 || len(p.Actions) != 0 {
			t.Errorf("unexpected usage batch: %+v", p)
		}
		if reject {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	opts := Options{DBPath: path, CloudURL: server.URL, InstallationID: "ins_test", InstallToken: "test"}
	if err := flushToolUsage(ctx, opts); err == nil {
		t.Fatal("expected upload failure")
	}
	reject = false
	if err := flushToolUsage(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if err := flushToolUsage(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if posts != 2 {
		t.Fatalf("posts=%d, want failed + successful retry", posts)
	}
}
