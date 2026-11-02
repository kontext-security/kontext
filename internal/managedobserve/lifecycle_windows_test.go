//go:build windows

package managedobserve

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"

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
