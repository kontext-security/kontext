//go:build windows

package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/kontext-security/kontext/internal/autostart"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/hook"
)

// What each way of dropping the RPC failed with on windows-latest and
// windows-11-arm (Go 1.26.10). Each is a lost connection and gets the retry; a
// slow reply is not.
func TestConnectionLostCoversWinsockDrops(t *testing.T) {
	failed := func(step, op string, err error) error {
		return fmt.Errorf("%s: %w", step, &net.OpError{Op: op, Net: "unix", Err: err})
	}
	for name, test := range map[string]struct {
		err  error
		lost bool
	}{
		// With or without the socket file the dead daemon left behind.
		"gone before the dial":    {&net.OpError{Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", windows.WSAECONNREFUSED)}, true},
		"closed during the write": {failed("write payload", "write", os.NewSyscallError("wsasend", windows.WSAECONNRESET)), true},
		// Also what a daemon killed after reading the request leaves.
		"closed with the request unread": {failed("read length", "read", os.NewSyscallError("wsarecv", windows.WSAECONNRESET)), true},
		"slow reply":                     {failed("read length", "read", os.ErrDeadlineExceeded), false},
	} {
		if got := connectionLost(test.err); got != test.lost {
			t.Errorf("%s: connectionLost(%v) = %v, want %v", name, test.err, got, test.lost)
		}
	}
}

// On Windows a daemon that closes the connection before reading the RPC resets
// it, as a daemon killed mid-RPC does. That is a restart too: the hook retries
// once, then fails open.
func TestLifecycleRetriesWhenDaemonClosesWithRequestUnread(t *testing.T) {
	socketPath := filepath.Join(hermetic.SocketDir(t), "kontext-managedobserve-reset.sock")
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 8)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
			accepted <- struct{}{}
		}
	}()

	lifecycle := Lifecycle{
		SocketPath: socketPath,
		Label:      DefaultLaunchdLabel,
		Mode:       "enforce",
		Kickstart: func(context.Context, string) error {
			t.Fatal("kickstart should not be called")
			return nil
		},
	}
	result := lifecycle.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	assertFailedOpen(t, result)
	// Each attempt is a probe and an RPC.
	for got := range 4 {
		select {
		case <-accepted:
		case <-time.After(2 * time.Second):
			t.Fatalf("daemon accepted %d connections, want 4: a probe and the dropped RPC, then both again for the retry", got)
		}
	}
}

// A hook starts the daemon the sign-in entry names, and nothing else.
func TestStartFromSignInEntry(t *testing.T) {
	program := filepath.Join(t.TempDir(), "kontextw.exe")
	if err := os.WriteFile(program, nil, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		entry     string
		entryErr  error
		wantStart bool
		wantErr   bool
	}{
		{name: "the entry setup writes", entry: autostart.Command(program), wantStart: true},
		{name: "no entry", entry: ""},
		{name: "an entry with other arguments", entry: `"` + program + `" something-else`, wantErr: true},
		{name: "an unquoted entry", entry: program + " " + autostart.DaemonSubcommand, wantErr: true},
		{name: "a program that is gone", entry: autostart.Command(program + ".old"), wantErr: true},
		{name: "an unreadable entry", entryErr: errors.New("access denied"), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var started []string
			err := startFromSignInEntry(
				func() (string, error) { return tc.entry, tc.entryErr },
				func(program string, args ...string) error {
					started = append([]string{program}, args...)
					return nil
				},
			)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want an error: %v", err, tc.wantErr)
			}
			if tc.wantStart != (len(started) > 0) {
				t.Fatalf("started %q, want a start: %v", started, tc.wantStart)
			}
			if tc.wantStart && (started[0] != program || len(started) != 2 || started[1] != autostart.DaemonSubcommand) {
				t.Fatalf("started %q, want the entry's program with the daemon's subcommand", started)
			}
		})
	}
}

// The hook's default start does nothing in a test: it would reach the real
// sign-in entry of the machine the test runs on.
func TestKickstartDaemonDoesNothingUnderTest(t *testing.T) {
	if err := kickstartDaemon(context.Background(), ""); err != nil {
		t.Fatalf("kickstartDaemon() = %v", err)
	}
}
