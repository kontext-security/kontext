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
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/instancelock"
	"github.com/kontext-security/kontext/internal/platform"
)

type instanceFixture struct {
	dir, socketPath, dbPath string
	opts                    DaemonOptions
}

func newInstanceFixture(t *testing.T) instanceFixture {
	t.Helper()
	hermetic.Home(t)
	// Windows takes the state folder from here, not from the home variables.
	t.Setenv("LOCALAPPDATA", t.TempDir())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	socketPath := filepath.Join(hermetic.SocketDir(t), "kontext.sock")
	dbPath := filepath.Join(dir, "guard.db")
	writeTestManagedConfigWithCloudURL(t, filepath.Join(dir, "managed.json"), server.URL)
	writeTestInstallation(t, filepath.Join(dir, "installation.json"))
	return instanceFixture{dir: dir, socketPath: socketPath, dbPath: dbPath, opts: DaemonOptions{
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

func shortInstanceWait(t *testing.T) {
	t.Helper()
	previous := instanceLockWait
	instanceLockWait = 100 * time.Millisecond
	t.Cleanup(func() { instanceLockWait = previous })
}

func TestRunDaemonRefusesWhileAnotherHoldsTheSocket(t *testing.T) {
	shortInstanceWait(t)
	fixture := newInstanceFixture(t)
	lockPath, err := instancelock.PathForSocket(fixture.socketPath)
	if err != nil {
		t.Fatal(err)
	}
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

// The lock can't see a daemon whose lock has another name, such as one running
// with another home. The socket shows it.
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
	lockPath, err := instancelock.PathForSocket(fixture.socketPath)
	if err != nil {
		t.Fatal(err)
	}
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
	deadline := time.Now().Add(10 * time.Second)
	for !socketAnswers(fixture.socketPath, diagnostic.Logger{}) {
		select {
		case err := <-errCh:
			errCh <- err
			t.Fatalf("RunDaemon() returned early: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon never answered on the socket")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A daemon on its way out still answers until it closes its socket, and it lets
// go of the lock after that. The check has to come after the wait for the lock,
// or a replacement started during the old one's shutdown would be refused.
func TestRunDaemonWaitsForADaemonThatIsLeaving(t *testing.T) {
	fixture := newInstanceFixture(t)
	lockPath, err := instancelock.PathForSocket(fixture.socketPath)
	if err != nil {
		t.Fatal(err)
	}
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
	deadline := time.Now().Add(10 * time.Second)
	for !socketAnswers(fixture.socketPath, diagnostic.Logger{}) {
		select {
		case err := <-errCh:
			errCh <- err
			t.Fatalf("RunDaemon() returned early: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the daemon never answered on the socket")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Without its lock, the daemon still won't take a socket from something alive.
func TestRunDaemonWithoutTheLockStillChecksTheSocket(t *testing.T) {
	fixture := newInstanceFixture(t)
	state, err := platform.UserStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "locks"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
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
	state, err := platform.UserStateDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "locks"), nil, 0o600); err != nil {
		t.Fatal(err)
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
	waitForSocket(t, fixture.socketPath, errCh)
}

func TestRunDaemonReleasesTheLockWhenItStops(t *testing.T) {
	fixture := newInstanceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- RunDaemon(ctx, fixture.opts) }()
	waitForSocket(t, fixture.socketPath, errCh)

	lockPath, err := instancelock.PathForSocket(fixture.socketPath)
	if err != nil {
		t.Fatal(err)
	}
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
	lockPath, err := instancelock.PathForSocket(fixture.socketPath)
	if err != nil {
		t.Fatal(err)
	}
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
