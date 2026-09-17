package main

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/kontext-security/kontext/internal/agent"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/managedobserve"
	"github.com/kontext-security/kontext/internal/runtimehost"
)

func TestFullDiskAccessResult(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want *bool
	}{
		{nil, boolValue(true)}, {io.EOF, boolValue(true)},
		{&fs.PathError{Op: "open", Path: "Mail", Err: syscall.EPERM}, boolValue(false)},
		{syscall.EACCES, nil}, {fs.ErrNotExist, nil}, {fs.ErrInvalid, nil},
	} {
		got := fullDiskAccessResult(tc.err)
		if (got == nil) != (tc.want == nil) || got != nil && *got != *tc.want {
			t.Fatalf("error %v: got %v, want %v", tc.err, got, tc.want)
		}
	}
}
func boolValue(value bool) *bool { return &value }

func TestFullDiskAccessProbe(t *testing.T) {
	dir := t.TempDir()
	if got := probeFullDiskAccess(dir); got == nil || !*got {
		t.Fatal("empty readable directory must be true")
	}
	if got := probeFullDiskAccess(filepath.Join(dir, "missing")); got != nil {
		t.Fatal("missing directory is unknown")
	}
}

func TestManagedHookFullDiskAccessReachesDaemonLedger(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, "Library", "Mail"), 0700); err != nil {
		t.Fatal(err)
	}
	a, _ := agent.Get("claude")
	event, err := (managedHookAgent{Agent: a}).DecodeHookInput([]byte(`{"session_id":"fda-test","hook_event_name":"PreToolUse","tool_name":"Read","tool_use_id":"fda-tool","tool_input":{"file_path":"/tmp/example"},"permission_mode":"default"}`))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "darwin" && (event.FullDiskAccess == nil || !*event.FullDiskAccess) {
		t.Fatal("managed hook skipped its FDA probe")
	}
	// The explicit false value must survive transport and deferred persistence too.
	event.FullDiskAccess = boolValue(false)
	ctx := context.Background()
	db := filepath.Join(t.TempDir(), "guard.db")
	host, err := runtimehost.Start(ctx, runtimehost.Options{AgentName: "claude", CWD: home, DBPath: db, AsyncDecisionRecording: true})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close(ctx)
	lifecycle := managedobserve.Lifecycle{SocketPath: host.SocketPath, Mode: "observe"}
	result := lifecycle.Process(ctx, event)
	if result.EventID == "" {
		t.Fatalf("no decision: %+v", result)
	}
	if err := host.Close(ctx); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.OpenStore(db)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rows, err := store.AuthorizationActions(ctx, sqlite.LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, row := range rows {
		if row["id"] != result.EventID {
			continue
		}
		found = true
		metadata := row["context_json"].(map[string]any)["hook_metadata"].(map[string]any)
		if metadata["full_disk_access"] != false || metadata["permission_mode"] != "default" {
			t.Fatalf("stored metadata = %#v", metadata)
		}
	}
	if !found {
		t.Fatal("decision absent from ledger")
	}
}
