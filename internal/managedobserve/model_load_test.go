package managedobserve

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
)

func modelLoadConfig() stepsafety.Config {
	return stepsafety.Config{Enabled: true, Timeout: time.Minute, StartupTimeout: time.Minute, MaxConcurrency: 1, ModelVersion: "test"}
}

// loadHeldUntil is a model load that lasts until the channel closes or the load is
// called off, so the daemon can't get anywhere by waiting for it.
func loadHeldUntil(release <-chan struct{}) func(context.Context) (stepsafety.Backend, error) {
	return func(ctx context.Context) (stepsafety.Backend, error) {
		select {
		case <-release:
			return &slowModel{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func preToolUse(toolUseID string) hook.Event {
	return hook.Event{
		SessionID:   "load-session",
		Agent:       "claude",
		HookName:    hook.HookPreToolUse,
		ToolName:    "mcp__files__delete_file",
		ToolUseID:   toolUseID,
		ToolInput:   map[string]any{"file_id": "report"},
		UserRequest: "tell me about the old quarterly report",
		CWD:         "/tmp/project",
	}
}

func countRows(t *testing.T, path, query string, args ...any) int {
	t.Helper()
	// This polls while the daemon writes.
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func waitForRows(t *testing.T, path, query string, want int, args ...any) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	got := 0
	for time.Now().Before(deadline) {
		if got = countRows(t, path, query, args...); got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%d rows, want %d: %s", got, want, query)
}

func awaitDaemonExit(t *testing.T, errCh <-chan error, within time.Duration) {
	t.Helper()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunDaemon() = %v", err)
		}
	case <-time.After(within):
		t.Fatalf("RunDaemon did not stop within %v", within)
	}
}

const scoredVerdicts = `select count(*) from step_safety_verdicts where tool_use_id = ? and error_code is null and unsafe_probability is not null`

// The load never finishes on its own here, so anything that waits for it fails.
func TestRunDaemonServesHooksWhileTheModelLoads(t *testing.T) {
	fixture := newInstanceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	fixture.opts.stepSafety = stepsafety.NewWithLoader(ctx, modelLoadConfig(), loadHeldUntil(release))
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	waitForSocket(t, fixture.socketPath, errCh)

	client := localruntime.NewClient(fixture.socketPath)
	client.Timeout = testRuntimeTimeout
	if _, err := client.Process(context.Background(), preToolUse("load-gated")); err != nil {
		t.Fatalf("gated hook during the load: %v", err)
	}

	completed := preToolUse("load-completed")
	completed.HookName = hook.HookPostToolUse
	if _, err := client.Process(context.Background(), completed); err != nil {
		t.Fatalf("non-gating hook during the load: %v", err)
	}
	// Kept while the model is still away, not only once it arrives.
	waitForRows(t, fixture.dbPath, `select count(*) from authorization_actions where tool_use_id = ?`, 1, "load-completed")
	if got := countRows(t, fixture.dbPath, `select count(*) from step_safety_verdicts`); got != 0 {
		t.Errorf("%d verdicts before the model is there", got)
	}

	close(release)
	waitForRows(t, fixture.dbPath, scoredVerdicts, 1, "load-gated")
	cancel()
	awaitDaemonExit(t, errCh, daemonStopBudget+10*time.Second)
}

// Halfway through the budget scoring stops anyway. A stop during the load shouldn't
// have to get that far, so the budget here is long enough to tell.
func TestRunDaemonStopsDuringTheModelLoad(t *testing.T) {
	previous := daemonStopBudget
	daemonStopBudget = 40 * time.Second
	t.Cleanup(func() { daemonStopBudget = previous })

	fixture := newInstanceFixture(t)
	log := &syncBuffer{}
	fixture.opts.Diagnostic = diagnostic.New(log, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	fixture.opts.stepSafety = stepsafety.NewWithLoader(ctx, modelLoadConfig(), loadHeldUntil(release))
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	waitForSocket(t, fixture.socketPath, errCh)

	const answered = 8 // More than the record workers, so some are still queued.
	client := localruntime.NewClient(fixture.socketPath)
	client.Timeout = testRuntimeTimeout
	for i := range answered {
		if _, err := client.Process(context.Background(), preToolUse("stop-"+string(rune('a'+i)))); err != nil {
			t.Fatalf("hook %d: %v", i, err)
		}
	}

	cancel()
	awaitDaemonExit(t, errCh, daemonStopBudget/2)
	if got := decidedRecords(t, fixture.dbPath); got != answered {
		t.Errorf("%d of %d answered calls have a record", got, answered)
	}
	if got := countRows(t, fixture.dbPath, `select count(*) from step_safety_verdicts where error_code = 'daemon_stopping'`); got != answered {
		t.Errorf("%d of %d verdicts say the daemon was stopping", got, answered)
	}
	if strings.Contains(log.String(), "shadow unavailable") {
		t.Errorf("a stop reads as a broken model: %q", log.String())
	}
}

func TestRunDaemonSaysSoWhenTheModelFailsToLoad(t *testing.T) {
	fixture := newInstanceFixture(t)
	log := &syncBuffer{}
	fixture.opts.Diagnostic = diagnostic.New(log, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture.opts.stepSafety = stepsafety.NewWithLoader(ctx, modelLoadConfig(), func(context.Context) (stepsafety.Backend, error) {
		return nil, errors.New("no weights")
	})
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	waitForSocket(t, fixture.socketPath, errCh)

	client := localruntime.NewClient(fixture.socketPath)
	client.Timeout = testRuntimeTimeout
	if _, err := client.Process(context.Background(), preToolUse("load-failed")); err != nil {
		t.Fatalf("hook after a failed load: %v", err)
	}
	waitForRows(t, fixture.dbPath, `select count(*) from step_safety_verdicts where tool_use_id = ? and shadow_decision = 'unavailable'`, 1, "load-failed")
	cancel()
	awaitDaemonExit(t, errCh, daemonStopBudget+10*time.Second)
	if !strings.Contains(log.String(), "step-safety shadow unavailable") {
		t.Errorf("the log doesn't say the model is unavailable: %q", log.String())
	}
}
