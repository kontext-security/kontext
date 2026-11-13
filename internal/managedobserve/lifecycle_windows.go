//go:build windows

package managedobserve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/kontext-security/kontext/internal/autostart"
)

// kickstartDaemon is what a hook does when nothing listens on the daemon's
// socket. Windows has no launchd to ask, so the hook starts the daemon
// itself, from the user's sign-in entry: the same program a sign-in starts.
// (To a test the machine has no entry, so a test starts nothing: autostart.)
func kickstartDaemon(context.Context, string) error {
	stamp := filepath.Join(filepath.Dir(DefaultSocketPath()), "daemon-start.stamp")
	return claimStart(stamp, func() error {
		return startFromSignInEntry(autostart.Entry, autostart.Start)
	})
}

// claimStart runs start unless another hook has started the daemon within
// the window, or is starting it at this moment. Hooks are separate
// processes, so the check and the mark are made under a named mutex: two
// hooks that find no daemon at the same instant would otherwise both pass
// the check before either had left its mark. Windows releases the mutex of a
// process that dies, so a hook killed half way blocks nobody. A mutex or a
// stamp that cannot be had costs the window, not the start.
func claimStart(stamp string, start func() error) error {
	// A mutex belongs to the thread that took it.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	sum := sha256.Sum256([]byte(strings.ToLower(stamp)))
	name, err := windows.UTF16PtrFromString(`Local\kontext-daemon-start-` + hex.EncodeToString(sum[:8]))
	if err != nil {
		return start()
	}
	// An existing mutex comes back as a handle together with an error.
	mutex, _ := windows.CreateMutex(nil, false, name)
	if mutex == 0 {
		return start()
	}
	defer windows.CloseHandle(mutex)
	event, err := windows.WaitForSingleObject(mutex, 0)
	if err != nil || (event != windows.WAIT_OBJECT_0 && event != windows.WAIT_ABANDONED) {
		return nil // another hook holds it: that one starts the daemon
	}
	defer windows.ReleaseMutex(mutex)
	if startInProgress(stamp, time.Now()) {
		return nil
	}
	// Before the start, so hooks arriving while the daemon loads see it.
	_ = os.WriteFile(stamp, nil, 0o600)
	return start()
}

// daemonStartWindow is how long one start of the daemon is given before a
// hook starts another. A daemon that comes up listens well inside it, and one
// that gives way to another waits as long for the other's lock. Without it
// every hook call that finds no daemon starts a process, and a daemon that
// cannot start at all gets one per call.
const daemonStartWindow = 5 * time.Second

// startInProgress reports a start another hook made within the window. The
// stamp is that start's mark; its age is all that counts, so a stale one
// needs no cleanup.
func startInProgress(stamp string, now time.Time) bool {
	info, err := os.Stat(stamp)
	if err != nil {
		return false
	}
	age := now.Sub(info.ModTime())
	return age >= 0 && age < daemonStartWindow
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
