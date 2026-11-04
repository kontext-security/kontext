package managedobserve

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
)

// A replacement waits instanceLockWait for the old daemon to leave. A stop that
// takes longer gets the replacement refused.
func TestDaemonStopBudgetIsBelowTheInstanceLockWait(t *testing.T) {
	if daemonStopBudget >= instanceLockWait {
		t.Errorf("stop budget %v, instance lock wait %v", daemonStopBudget, instanceLockWait)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// holdStoreWriteLock keeps every writer of the store waiting, so answered hooks
// pile up as records nobody has written yet. The returned func lets go.
func holdStoreWriteLock(t *testing.T, path string) func() {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "begin immediate"); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			_, _ = conn.ExecContext(context.Background(), "rollback")
			conn.Close()
			db.Close()
		})
	}
	t.Cleanup(release)
	return release
}

func fireAnsweredHooks(t *testing.T, socketPath string, count int) {
	t.Helper()
	client := localruntime.NewClient(socketPath)
	client.Timeout = testRuntimeTimeout
	for i := range count {
		if _, err := client.Process(context.Background(), hook.Event{
			SessionID: "stop-session",
			Agent:     "claude",
			HookName:  hook.HookPreToolUse,
			ToolName:  "Read",
			ToolUseID: fmt.Sprintf("stop-%d", i),
			CWD:       "/tmp/project",
		}); err != nil {
			t.Fatalf("hook %d: %v", i, err)
		}
	}
}

func fireAnsweredEvents(t *testing.T, socketPath string, count int) {
	t.Helper()
	client := localruntime.NewClient(socketPath)
	client.Timeout = testRuntimeTimeout
	for i := range count {
		if _, err := client.Process(context.Background(), hook.Event{
			SessionID: "stop-session",
			Agent:     "claude",
			HookName:  hook.HookPostToolUse,
			ToolName:  "Read",
			ToolUseID: fmt.Sprintf("stop-event-%d", i),
			CWD:       "/tmp/project",
		}); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
	}
}

func decidedRecords(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`select count(distinct tool_use_id) from authorization_actions
		where canonical_event_type = 'request.decided' and tool_use_id like 'stop-%'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestRunDaemonWritesQueuedRecordsWhenStopped(t *testing.T) {
	fixture := newInstanceFixture(t)
	log := &syncBuffer{}
	fixture.opts.Diagnostic = diagnostic.New(log, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	waitForSocket(t, fixture.socketPath, errCh)

	release := holdStoreWriteLock(t, fixture.dbPath)
	const answered = 10
	fireAnsweredHooks(t, fixture.socketPath, answered)
	if got := decidedRecords(t, fixture.dbPath); got != 0 {
		t.Fatalf("%d records were written under the lock, so nothing is queued", got)
	}

	cancel()
	time.AfterFunc(300*time.Millisecond, release)
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunDaemon() = %v", err)
		}
	case <-time.After(daemonStopBudget + 2*time.Second):
		t.Fatal("RunDaemon did not stop")
	}
	if got := decidedRecords(t, fixture.dbPath); got != answered {
		t.Errorf("%d of %d answered calls have a record", got, answered)
	}
	if got := log.String(); strings.Contains(got, "not written") {
		t.Errorf("the log reports records left after all were written: %q", got)
	}
}

func TestRunDaemonStopsByItsDeadlineAndSaysWhatIsLeft(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the daemon leaves its store open past the deadline, and Windows can't then remove the test's folder")
	}
	previous := daemonStopBudget
	daemonStopBudget = 400 * time.Millisecond
	t.Cleanup(func() { daemonStopBudget = previous })

	fixture := newInstanceFixture(t)
	log := &syncBuffer{}
	fixture.opts.Diagnostic = diagnostic.New(log, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	waitForSocket(t, fixture.socketPath, errCh)

	holdStoreWriteLock(t, fixture.dbPath)
	fireAnsweredHooks(t, fixture.socketPath, 5)
	fireAnsweredEvents(t, fixture.socketPath, 3)

	started := time.Now()
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunDaemon() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunDaemon waited past its deadline for records it can't write")
	}
	if took := time.Since(started); took > 2*time.Second {
		t.Errorf("the stop took %v with a budget of %v", took, daemonStopBudget)
	}
	if got := log.String(); !strings.Contains(got, "8 records not written") {
		t.Errorf("the log doesn't say what was left: %q", got)
	}
}

// A cleanup tick on a busy store mustn't hold the stop up, or the stop's deadline
// wouldn't start until the tick gave up.
func TestRunDaemonStopsDuringACleanupTick(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the daemon leaves its store open past the deadline, and Windows can't then remove the test's folder")
	}
	previous := daemonStopBudget
	daemonStopBudget = 400 * time.Millisecond
	t.Cleanup(func() { daemonStopBudget = previous })

	fixture := newInstanceFixture(t)
	fixture.opts.IdleTimeout = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	waitForSocket(t, fixture.socketPath, errCh)

	holdStoreWriteLock(t, fixture.dbPath)
	time.Sleep(300 * time.Millisecond) // Long enough for a tick to meet the lock.

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunDaemon() = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the stop waited behind a cleanup tick")
	}
}

// slowModel stands in for the model, so a backlog forms however fast the machine
// is and doesn't depend on how busy it is.
type slowModel struct{ calls atomic.Int64 }

func (m *slowModel) Infer(context.Context, stepsafety.Input) (stepsafety.InferenceResult, error) {
	m.calls.Add(1)
	time.Sleep(500 * time.Millisecond)
	return stepsafety.InferenceResult{}, nil
}

func (m *slowModel) Health(context.Context) (stepsafety.Health, error) {
	return stepsafety.Health{}, nil
}

func (m *slowModel) Close() error { return nil }

// The model takes far longer a record than a write does, so a backlog bigger than
// the budget still fits once the model is out of the way. Scoring all of these
// would take twice the budget.
func TestRunDaemonStopsScoringToWriteABacklog(t *testing.T) {
	previous := daemonStopBudget
	daemonStopBudget = 6 * time.Second
	t.Cleanup(func() { daemonStopBudget = previous })

	fixture := newInstanceFixture(t)
	log := &syncBuffer{}
	fixture.opts.Diagnostic = diagnostic.New(log, true)
	model := &slowModel{}
	fixture.opts.stepSafety = stepsafety.NewWithBackend(model, time.Minute, 4, "test")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	waitForSocket(t, fixture.socketPath, errCh)

	const answered = 100
	client := localruntime.NewClient(fixture.socketPath)
	client.Timeout = testRuntimeTimeout
	for i := range answered {
		if _, err := client.Process(context.Background(), hook.Event{
			SessionID:   "stop-session",
			Agent:       "claude",
			HookName:    hook.HookPreToolUse,
			ToolName:    "mcp__files__delete_file",
			ToolUseID:   fmt.Sprintf("stop-%d", i),
			ToolInput:   map[string]any{"file_id": fmt.Sprintf("report-%d", i)},
			UserRequest: "tell me about the old quarterly report",
			CWD:         "/tmp/project",
		}); err != nil {
			t.Fatalf("hook %d: %v", i, err)
		}
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunDaemon() = %v", err)
		}
	case <-time.After(daemonStopBudget + 10*time.Second):
		t.Fatal("RunDaemon did not stop")
	}
	if got := decidedRecords(t, fixture.dbPath); got != answered {
		t.Errorf("%d of %d answered calls have a record; log: %q", got, answered, log.String())
	}
	if got := model.calls.Load(); got == 0 || got >= answered {
		t.Errorf("the model ran %d times for %d calls, so it wasn't cut off part way", got, answered)
	}
	db, err := sql.Open("sqlite", fixture.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var unscored int
	if err := db.QueryRow(`select count(*) from step_safety_verdicts where error_code = 'unavailable'`).Scan(&unscored); err != nil {
		t.Fatal(err)
	}
	if int64(unscored) != answered-model.calls.Load() {
		t.Errorf("%d verdicts say unavailable, want one for each of the %d calls the model didn't see", unscored, answered-model.calls.Load())
	}
}

func TestStopWaitGivesUpOnWorkThatWontEnd(t *testing.T) {
	previous := daemonStopBudget
	daemonStopBudget = 150 * time.Millisecond
	t.Cleanup(func() { daemonStopBudget = previous })
	var stuck sync.WaitGroup
	stuck.Add(1)
	defer stuck.Done()
	log := &syncBuffer{}

	returned := make(chan struct{})
	go func() {
		waitForBackgroundWork(&stuck, diagnostic.New(log, true))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the stop waited on work that won't end")
	}
	if !strings.Contains(log.String(), "background work still running") {
		t.Errorf("the log doesn't say so: %q", log.String())
	}

	var done sync.WaitGroup
	log = &syncBuffer{}
	waitForBackgroundWork(&done, diagnostic.New(log, true))
	if log.String() != "" {
		t.Errorf("finished work read as still running: %q", log.String())
	}
}

// All the steps of a stop share one deadline, or each would get the whole budget.
func TestStopClockKeepsOneDeadline(t *testing.T) {
	clock := &stopClock{}
	first, cancelFirst := clock.context()
	defer cancelFirst()
	time.Sleep(20 * time.Millisecond)
	second, cancelSecond := clock.context()
	defer cancelSecond()
	want, _ := first.Deadline()
	if got, _ := second.Deadline(); !got.Equal(want) {
		t.Errorf("the deadline moved from %v to %v", want, got)
	}
}

const stopHelperEnv = "KONTEXT_STOP_SIGNAL_TEST_HELPER"

// TestStopSignalHelper is the process the signal tests stop. It isn't a test.
func TestStopSignalHelper(t *testing.T) {
	mode := os.Getenv(stopHelperEnv)
	if mode == "" {
		t.Skip("runs only as a helper process")
	}
	ctx, release := StopOnSignal(context.Background(), diagnostic.New(os.Stderr, false))
	defer release()
	fmt.Println("ready")
	<-ctx.Done()
	fmt.Println("stopping")
	if mode == "stuck" {
		time.Sleep(time.Minute)
	}
	fmt.Println("stopped")
}

func startStopHelper(t *testing.T, mode string) (*exec.Cmd, *bufio.Scanner, *bytes.Buffer) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestStopSignalHelper$")
	cmd.Env = append(os.Environ(), stopHelperEnv+"="+mode)
	prepareStopHelper(cmd)
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	lines := bufio.NewScanner(stdout)
	waitForLine(t, lines, "ready")
	return cmd, lines, stderr
}

func waitForLine(t *testing.T, lines *bufio.Scanner, want string) {
	t.Helper()
	found := make(chan bool, 1)
	go func() {
		for lines.Scan() {
			if strings.TrimSpace(lines.Text()) == want {
				found <- true
				return
			}
		}
		found <- false
	}()
	select {
	case ok := <-found:
		if !ok {
			t.Fatalf("the helper ended without saying %q", want)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the helper never said %q", want)
	}
}

func TestStopSignalLetsTheDaemonFinish(t *testing.T) {
	cmd, lines, _ := startStopHelper(t, "stop")
	sendStopSignal(t, cmd)
	waitForLine(t, lines, "stopping")
	waitForLine(t, lines, "stopped")
}

func TestSecondStopSignalExitsAtOnce(t *testing.T) {
	cmd, lines, stderr := startStopHelper(t, "stuck")
	sendStopSignal(t, cmd)
	waitForLine(t, lines, "stopping")
	sendStopSignal(t, cmd)
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != secondStopSignalExit {
			t.Errorf("exit = %v, want code %d", err, secondStopSignalExit)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a second signal didn't end a stuck stop")
	}
	if !strings.Contains(stderr.String(), "second stop signal") {
		t.Errorf("stderr doesn't say why: %q", stderr.String())
	}
}
