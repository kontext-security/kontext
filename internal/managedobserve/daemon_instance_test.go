package managedobserve

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/instancelock"
)

type instanceFixture struct {
	dir, socketPath, dbPath string
	opts                    DaemonOptions
	// log is what the fixture's daemon wrote to its diagnostic log, each
	// line with the time since the fixture was made.
	log *stampedLog
}

// stampedLog keeps what is written to it, each write behind the time since
// start.
type stampedLog struct {
	syncBuffer
	start time.Time
}

func (l *stampedLog) Write(p []byte) (int, error) {
	if _, err := l.syncBuffer.Write([]byte(time.Since(l.start).Round(time.Millisecond).String() + " " + string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

func newInstanceFixture(t *testing.T) instanceFixture {
	t.Helper()
	return newInstanceFixtureIn(t, t.TempDir())
}

// newInstanceFixtureIn is newInstanceFixture with the daemon's store and
// state in dir.
func newInstanceFixtureIn(t *testing.T, dir string) instanceFixture {
	t.Helper()
	hermetic.Home(t)
	// Windows keeps its state here, not under the home variables.
	t.Setenv("LOCALAPPDATA", t.TempDir())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	socketPath := filepath.Join(hermetic.SocketDir(t), "kontext.sock")
	dbPath := filepath.Join(dir, "guard.db")
	writeTestManagedConfigWithCloudURL(t, filepath.Join(dir, "managed.json"), server.URL)
	writeTestInstallation(t, filepath.Join(dir, "installation.json"))
	// The daemon's log goes to the fixture, not to stderr, and a failed test
	// shows it with times, so a daemon that hangs names where.
	log := &stampedLog{start: time.Now()}
	t.Cleanup(func() {
		if logged := log.String(); t.Failed() && logged != "" {
			t.Logf("the daemon logged:\n%s", logged)
		}
	})
	return instanceFixture{dir: dir, socketPath: socketPath, dbPath: dbPath, log: log, opts: DaemonOptions{
		Diagnostic:       diagnostic.New(log, true),
		SocketPath:       socketPath,
		DBPath:           dbPath,
		IdleTimeout:      time.Hour,
		StreamStatePath:  filepath.Join(dir, "stream-state.json"),
		StreamInterval:   time.Hour,
		StreamHTTPClient: server.Client(),
		PolicyHTTPClient: server.Client(),
		BinaryVersion:    "test",
	}}
}

// waitForAnswer waits until the daemon started in errCh answers on the
// fixture's socket. A daemon that does not is reported with what the last
// check of the socket said; the fixture adds what the daemon logged.
func (f instanceFixture) waitForAnswer(t *testing.T, errCh chan error) {
	t.Helper()
	checks := &syncBuffer{}
	deadline := time.Now().Add(10 * time.Second)
	for !socketAnswers(f.socketPath, diagnostic.New(checks, true)) {
		select {
		case err := <-errCh:
			errCh <- err
			t.Fatalf("RunDaemon() returned early: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			lines := strings.Split(strings.TrimSpace(checks.String()), "\n")
			t.Fatalf("the daemon never answered on the socket; the last check said: %s", lines[len(lines)-1])
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// blockInstanceLock puts a folder where the lock file goes, which no open takes.
func blockInstanceLock(t *testing.T, socketPath string) {
	t.Helper()
	if err := EnsureSocketDir(socketPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(instancelock.PathForSocket(socketPath), 0o700); err != nil {
		t.Fatal(err)
	}
}

func shortInstanceWait(t *testing.T) {
	t.Helper()
	previous := instanceLockWait
	instanceLockWait = 100 * time.Millisecond
	t.Cleanup(func() { instanceLockWait = previous })
}

func TestRunDaemonRefusesWhileAnotherHoldsTheSocket(t *testing.T) {
	shortInstanceWait(t)
	fixture := newInstanceFixture(t)
	lockPath := instancelock.PathForSocket(fixture.socketPath)
	holder, err := instancelock.Acquire(lockPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	// Stands in for the live daemon's socket, which a refused start must leave.
	if err := EnsureSocketDir(fixture.socketPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.socketPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// Bounded, so a daemon that wrongly starts fails this test and doesn't hang it.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = RunDaemon(ctx, fixture.opts)
	var held *instancelock.HeldError
	if !errors.As(err, &held) {
		t.Fatalf("RunDaemon() = %v, want a refusal naming the holder", err)
	}
	if _, statErr := os.Stat(fixture.socketPath); statErr != nil {
		t.Errorf("the refused start removed the live socket: %v", statErr)
	}
	if _, statErr := os.Stat(fixture.dbPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the refused start opened the store: %v", statErr)
	}
}

// The host trims the path before it binds, so the lock has to go by the trimmed
// path too, or the same socket has two locks.
func TestRunDaemonLocksTheSocketItWillBind(t *testing.T) {
	shortInstanceWait(t)
	fixture := newInstanceFixture(t)
	if err := EnsureSocketDir(fixture.socketPath); err != nil {
		t.Fatal(err)
	}
	holder, err := instancelock.Acquire(instancelock.PathForSocket(fixture.socketPath), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()

	fixture.opts.SocketPath = fixture.socketPath + " "
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = RunDaemon(ctx, fixture.opts)
	var held *instancelock.HeldError
	if !errors.As(err, &held) {
		t.Fatalf("RunDaemon() = %v, want a refusal naming the holder", err)
	}
}

// The lock can't see a daemon that takes none, such as one from an older release.
// The socket shows it.
func TestRunDaemonRefusesWhenSomethingAnswersOnTheSocket(t *testing.T) {
	fixture := newInstanceFixture(t)
	if err := EnsureSocketDir(fixture.socketPath); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", fixture.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = RunDaemon(ctx, fixture.opts)
	if err == nil || !strings.Contains(err.Error(), fixture.socketPath) {
		t.Fatalf("RunDaemon() = %v, want a refusal naming the socket", err)
	}
	if !socketAnswers(fixture.socketPath, diagnostic.Logger{}) {
		t.Error("the refused start took the socket away")
	}
	if _, statErr := os.Stat(fixture.dbPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("the refused start opened the store: %v", statErr)
	}
	lockPath := instancelock.PathForSocket(fixture.socketPath)
	lock, err := instancelock.Acquire(lockPath, 0)
	if err != nil {
		t.Fatalf("the refused start kept the lock: %v", err)
	}
	lock.Release()
}

// A crash leaves the socket file behind, with nothing answering. That must not
// keep the next daemon out.
func TestRunDaemonReplacesASocketNothingAnswersOn(t *testing.T) {
	fixture := newInstanceFixture(t)
	if err := EnsureSocketDir(fixture.socketPath); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", fixture.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	listener.(*net.UnixListener).SetUnlinkOnClose(false)
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(fixture.socketPath); err != nil {
		t.Fatalf("no stale socket to test with: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	defer func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("RunDaemon() = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("RunDaemon did not stop")
		}
	}()
	fixture.waitForAnswer(t, errCh)
}

// A daemon on its way out still answers until it closes its socket, and it lets
// go of the lock after that. The check has to come after the wait for the lock,
// or a replacement started during the old one's shutdown would be refused.
func TestRunDaemonWaitsForADaemonThatIsLeaving(t *testing.T) {
	fixture := newInstanceFixture(t)
	lockPath := instancelock.PathForSocket(fixture.socketPath)
	holder, err := instancelock.Acquire(lockPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()
	if err := EnsureSocketDir(fixture.socketPath); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", fixture.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	time.AfterFunc(300*time.Millisecond, func() {
		_ = listener.Close()
		holder.Release()
	})

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	defer func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("RunDaemon() = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("RunDaemon did not stop")
		}
	}()
	time.Sleep(400 * time.Millisecond) // Past the old daemon's exit.
	fixture.waitForAnswer(t, errCh)
}

func TestConnectFailureMeansBusy(t *testing.T) {
	dial := func(err error) error { return &net.OpError{Op: "dial", Net: "unix", Err: err} }
	for name, tt := range map[string]struct {
		err  error
		want bool
	}{
		"queue full": {dial(os.NewSyscallError("connect", syscall.EAGAIN)), true},
		"timed out":  {dial(os.ErrDeadlineExceeded), true},
		"refused":    {dial(os.NewSyscallError("connect", syscall.ECONNREFUSED)), false},
		"no file":    {dial(os.NewSyscallError("connect", syscall.ENOENT)), false},
		"not a dial": {errors.New("something else"), false},
	} {
		if got := connectFailureMeansBusy(tt.err); got != tt.want {
			t.Errorf("%s: got %t, want %t", name, got, tt.want)
		}
	}
}

// Without its lock, the daemon still won't take a socket from something alive.
func TestRunDaemonWithoutTheLockStillChecksTheSocket(t *testing.T) {
	fixture := newInstanceFixture(t)
	blockInstanceLock(t, fixture.socketPath)
	if err := EnsureSocketDir(fixture.socketPath); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", fixture.socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := RunDaemon(ctx, fixture.opts); err == nil || !strings.Contains(err.Error(), fixture.socketPath) {
		t.Fatalf("RunDaemon() = %v, want a refusal naming the socket", err)
	}
}

// Whatever keeps the lock from working, a daemon without the guard beats none:
// hooks fail open with no daemon.
func TestRunDaemonStartsWhenTheLockCannotBeTaken(t *testing.T) {
	fixture := newInstanceFixture(t)
	blockInstanceLock(t, fixture.socketPath)

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	defer func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("RunDaemon() = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("RunDaemon did not stop")
		}
	}()
	waitForSocket(t, fixture.socketPath, errCh)
}

func TestRunDaemonReleasesTheLockWhenItStops(t *testing.T) {
	fixture := newInstanceFixture(t)
	// A socket folder that isn't there yet: the daemon has to prepare and check
	// it before taking the lock, or it runs without the lock.
	fixture.socketPath = filepath.Join(filepath.Dir(fixture.socketPath), "new", "s.sock")
	fixture.opts.SocketPath = fixture.socketPath
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	waitForSocket(t, fixture.socketPath, errCh)

	lockPath := instancelock.PathForSocket(fixture.socketPath)
	if lock, err := instancelock.Acquire(lockPath, 0); err == nil {
		lock.Release()
		t.Fatal("the running daemon doesn't hold the lock")
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunDaemon() = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunDaemon did not stop")
	}
	lock, err := instancelock.Acquire(lockPath, 0)
	if err != nil {
		t.Fatalf("the stopped daemon still holds the lock: %v", err)
	}
	lock.Release()
}

// A parked agent serves nothing, so it must not keep the daemon that should
// serve from starting.
func TestRunDaemonParkedDoesNotTakeTheLock(t *testing.T) {
	shortInstanceWait(t)
	fixture := newInstanceFixture(t)
	t.Setenv(EnvExpectedConfigScope, "user") // The config resolves as scope "env".
	lockPath := instancelock.PathForSocket(fixture.socketPath)
	holder, err := instancelock.Acquire(lockPath, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Release()

	// With the lock already held, a daemon that asks for it is refused; only one
	// that parks first waits for the context and returns nil.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := RunDaemon(ctx, fixture.opts); err != nil {
		t.Fatalf("RunDaemon() = %v, want a park until the context ends", err)
	}
}
