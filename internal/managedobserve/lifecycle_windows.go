//go:build windows

package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/kontext-security/kontext/internal/autostart"
)

// kickstartDaemon is what a hook does when nothing listens on the daemon's
// socket. Windows has no launchd to ask, so the hook starts the daemon
// itself, from the user's sign-in entry: the same program a sign-in starts.
//
// Under `go test` it does nothing. A test's home does not cover the registry,
// so a test that got here would start the daemon of the real install on the
// machine it runs on.
func kickstartDaemon(context.Context, string) error {
	if testing.Testing() {
		return nil
	}
	return startFromSignInEntry(autostart.Entry, autostart.Start)
}

// startFromSignInEntry starts the daemon the sign-in entry names, and only
// that: the entry has to be the one setup writes, for a program that exists.
// No entry means no user install here (a machine-wide install's logon task
// looks after its own daemon), or one that uninstall has just taken away,
// and nothing is started. A second daemon gives way to one that is already
// coming up, so two hooks at once leave one.
func startFromSignInEntry(entry func() (string, error), start func(string, ...string) error) error {
	value, err := entry()
	if err != nil {
		return fmt.Errorf("read the sign-in entry: %w", err)
	}
	if value == "" {
		return nil
	}
	program := autostart.Program(value)
	if !filepath.IsAbs(program) || value != autostart.Command(program) {
		return errors.New("the sign-in entry is not the one kontext setup writes")
	}
	if !regularFile(program) {
		return fmt.Errorf("the sign-in entry starts a program that is not there: %s", program)
	}
	return start(program, autostart.DaemonSubcommand)
}

// winsockConnectionLost matches the Winsock errnos a dropped connection fails
// with on Windows. syscall.ECONNRESET and the rest are Go's own numbers there,
// which no socket error equals. A daemon that closes before reading the RPC,
// or dies holding it even after reading it, resets the hook's write or read
// with WSAECONNRESET. A dial after it is refused with WSAECONNREFUSED, whether
// or not the socket file is left behind.
func winsockConnectionLost(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, windows.WSAECONNREFUSED)
}
