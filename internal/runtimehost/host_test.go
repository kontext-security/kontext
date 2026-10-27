package runtimehost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
)

func TestCloseKeepsResourcesAliveWhenRecordDrainTimesOut(t *testing.T) {
	var drainCalls, closed int
	host := &Host{
		drainRecords: func(ctx context.Context) error {
			drainCalls++
			if drainCalls == 1 {
				return context.DeadlineExceeded
			}
			return nil
		},
		closeStore:      func() error { closed++; return nil },
		closeStepSafety: func() error { closed++; return nil },
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := host.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close error=%v", err)
	}
	if closed != 0 || host.drainRecords == nil {
		t.Fatal("timed-out drain closed pending work's resources")
	}
	if err := host.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if closed != 2 || drainCalls != 2 {
		t.Fatalf("closed=%d drains=%d", closed, drainCalls)
	}
}

func TestStartMerlinDefaultAndOptOut(t *testing.T) {
	for _, tc := range []struct {
		name, flag string
		enabled    bool
	}{{"default", "", true}, {"opt-out", "0", false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KONTEXT_STEP_SAFETY_SHADOW", tc.flag)
			ctx := context.Background()
			dbPath := filepath.Join(t.TempDir(), "guard.db")
			host, err := Start(ctx, Options{AgentName: "claude", CWD: t.TempDir(), DBPath: dbPath})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = host.Close(ctx) })
			if (host.drainRecords != nil) != tc.enabled {
				t.Fatal("Merlin must select deferred recording even without AsyncDecisionRecording")
			}
			client := localruntime.NewClient(host.SocketPath)
			result, err := client.Process(ctx, hook.Event{
				Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Read",
				ToolInput: map[string]any{"file_path": "README.md"},
			})
			if err != nil || result.Decision != hook.DecisionAllow {
				t.Fatalf("result=%+v error=%v, want unchanged allow", result, err)
			}
			if err := host.Close(ctx); err != nil {
				t.Fatal(err)
			}
			store, err := sqlite.OpenStore(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			verdicts, err := store.StepSafetyVerdictsForSession(ctx, host.SessionID)
			if err != nil {
				t.Fatal(err)
			}
			if !tc.enabled {
				if len(verdicts) != 0 {
					t.Fatal("opt-out still recorded Merlin annotations")
				}
				return
			}
			if len(verdicts) != 1 || verdicts[0].ModelVersion != stepsafety.ModelVersion || verdicts[0].Enforced || verdicts[0].ErrorCode != stepsafety.ErrorExcludedTool {
				t.Fatalf("default-on annotation missing or changed: %+v", verdicts)
			}
		})
	}
}

func TestStartWorksOutsideRepoCWD(t *testing.T) {
	t.Chdir(t.TempDir())

	host, err := Start(context.Background(), Options{
		AgentName: "claude",
		CWD:       t.TempDir(),
		DBPath:    filepath.Join(t.TempDir(), "guard.db"),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer host.Close(context.Background())
}

func TestStartUsesFullSessionIDForSessionDir(t *testing.T) {
	sessionID := "1234567890abcdef1234567890abcdef"
	host, err := Start(context.Background(), Options{
		AgentName: "claude",
		SessionID: sessionID,
		CWD:       t.TempDir(),
		DBPath:    filepath.Join(t.TempDir(), "guard.db"),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer host.Close(context.Background())

	if got, want := filepath.Base(host.SessionDir), sessionID; got != want {
		t.Fatalf("session dir base = %q, want %q", got, want)
	}
	if got, want := filepath.Dir(host.SessionDir), sessionRootDir(); got != want {
		t.Fatalf("session dir parent = %q, want %q", got, want)
	}
}

func TestSessionRootDirIsPerUser(t *testing.T) {
	root := sessionRootDir()
	if runtime.GOOS == "windows" {
		if want := filepath.Join(os.TempDir(), "kontext"); root != want {
			t.Fatalf("sessionRootDir() = %q, want %q", root, want)
		}
		return
	}
	if want := filepath.Join("/tmp", fmt.Sprintf("kontext-%d", os.Getuid())); root != want {
		t.Fatalf("sessionRootDir() = %q, want %q", root, want)
	}
}

func TestStartRejectsUnsafeSessionID(t *testing.T) {
	for _, sessionID := range []string{"../escape", "nested/path", `nested\path`, ".", "..", "bad id"} {
		t.Run(sessionID, func(t *testing.T) {
			host, err := Start(context.Background(), Options{
				AgentName: "claude",
				SessionID: sessionID,
				CWD:       t.TempDir(),
				DBPath:    filepath.Join(t.TempDir(), "guard.db"),
			})
			if err == nil {
				_ = host.Close(context.Background())
				t.Fatal("Start() error = nil, want unsafe session ID error")
			}
		})
	}
}

func TestStartDoesNotChmodCustomDBParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "project")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}
	host, err := Start(context.Background(), Options{
		AgentName: "claude",
		CWD:       t.TempDir(),
		DBPath:    filepath.Join(parent, "guard.db"),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer host.Close(context.Background())

	info, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("custom DB parent mode = %o, want 755", got)
	}
}

func TestStartPersistsLocalDecisions(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	host, err := Start(ctx, Options{
		AgentName:  "claude",
		CWD:        t.TempDir(),
		DBPath:     dbPath,
		Diagnostic: diagnostic.New(nil, false),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := localruntime.NewClient(host.SocketPath)
	result, err := client.Process(ctx, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
		ToolInput: map[string]any{
			"command": "rm -rf /tmp/kontext-test",
		},
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision == "" {
		t.Fatal("result decision is empty")
	}
	sessionID := host.SessionID
	if err := host.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	defer store.Close()
	events, err := store.Events(ctx, sessionID)
	if err != nil {
		t.Fatalf("Events() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1", len(events))
	}
	if string(events[0].Decision) != string(result.Decision) {
		t.Fatalf("stored decision = %q, want %q", events[0].Decision, result.Decision)
	}
}

func TestCloseDrainsAsyncTelemetryBeforeClosingSession(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	host, err := Start(ctx, Options{
		AgentName:  "claude",
		CWD:        t.TempDir(),
		DBPath:     dbPath,
		Diagnostic: diagnostic.New(nil, false),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := localruntime.NewClient(host.SocketPath)
	result, err := client.Process(ctx, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPostToolUse,
		ToolName: "Bash",
		ToolInput: map[string]any{
			"command": "echo done",
		},
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("post-tool decision = %q, want allow ack", result.Decision)
	}
	sessionID := host.SessionID
	if err := host.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	defer store.Close()
	batch, err := store.LedgerBatch(ctx, sqlite.LedgerExportOptions{})
	if err != nil {
		t.Fatalf("LedgerBatch() error = %v", err)
	}
	if len(batch.Actions) != 1 || batch.Actions[0]["canonical_event_type"] != "request.observed" {
		t.Fatalf("actions = %+v, want drained observed telemetry action", batch.Actions)
	}
	session, err := store.Session(ctx, sessionID)
	if err != nil {
		t.Fatalf("Session() error = %v", err)
	}
	if session.Status != "closed" {
		t.Fatalf("session status = %q, want closed", session.Status)
	}
}
