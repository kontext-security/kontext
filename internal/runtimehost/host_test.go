package runtimehost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/localruntime"
)

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

func TestStartRejectsUnsafeSessionIDBeforeJudgeConfig(t *testing.T) {
	t.Setenv("KONTEXT_JUDGE_TIMEOUT", "not-a-duration")

	host, err := Start(context.Background(), Options{
		AgentName:          "claude",
		SessionID:          "../escape",
		CWD:                t.TempDir(),
		DBPath:             filepath.Join(t.TempDir(), "guard.db"),
		JudgeConfigFromEnv: true,
	})
	if err == nil {
		_ = host.Close(context.Background())
		t.Fatal("Start() error = nil, want unsafe session ID error")
	}
	if strings.Contains(err.Error(), "KONTEXT_JUDGE_TIMEOUT") {
		t.Fatalf("error = %v, want session ID validation before judge config", err)
	}
	if !strings.Contains(err.Error(), "runtime session ID") {
		t.Fatalf("error = %v, want unsafe session ID error", err)
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

func TestStartWiresLocalJudgeFromEnv(t *testing.T) {
	ctx := context.Background()
	judgeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("judge path = %q, want /v1/chat/completions", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"{\"decision\":\"deny\",\"risk_level\":\"high\",\"categories\":[\"test\"],\"reason\":\"test judge deny\"}"}}]}`))
	}))
	defer judgeServer.Close()
	t.Setenv("KONTEXT_JUDGE_URL", judgeServer.URL)
	t.Setenv("KONTEXT_JUDGE_MODEL", "test-local-judge")

	dbPath := filepath.Join(t.TempDir(), "guard.db")
	host, err := Start(ctx, Options{
		AgentName:          "claude",
		CWD:                t.TempDir(),
		DBPath:             dbPath,
		JudgeConfigFromEnv: true,
		Diagnostic:         diagnostic.New(nil, false),
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	client := localruntime.NewClient(host.SocketPath)
	_, err = client.Process(ctx, hook.Event{
		Agent:    "claude",
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
		ToolInput: map[string]any{
			"command": "echo hello",
		},
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
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
	if events[0].Decision != risk.DecisionDeny || events[0].RiskEvent.DecisionStage != risk.DecisionStageJudgeDeny {
		t.Fatalf("stored decision = %q stage = %q, want judge deny", events[0].Decision, events[0].RiskEvent.DecisionStage)
	}
	if events[0].RiskEvent.JudgeModel != "test-local-judge" {
		t.Fatalf("judge model = %q, want test-local-judge", events[0].RiskEvent.JudgeModel)
	}
}

func TestStartIgnoresJudgeEnvUnlessEnabled(t *testing.T) {
	t.Setenv("KONTEXT_JUDGE_TIMEOUT", "not-a-duration")

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

func TestStartValidatesJudgeEnvWhenEnabled(t *testing.T) {
	t.Setenv("KONTEXT_JUDGE_TIMEOUT", "not-a-duration")

	host, err := Start(context.Background(), Options{
		AgentName:          "claude",
		CWD:                t.TempDir(),
		DBPath:             filepath.Join(t.TempDir(), "guard.db"),
		JudgeConfigFromEnv: true,
	})
	if err == nil {
		_ = host.Close(context.Background())
		t.Fatal("Start() error = nil, want judge env validation error")
	}
	if !strings.Contains(err.Error(), "KONTEXT_JUDGE_TIMEOUT") {
		t.Fatalf("error = %v, want judge timeout error", err)
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
