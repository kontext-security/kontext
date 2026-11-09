package main

import (
	"log"
	"os"
	"runtime/debug"

	"golang.org/x/sys/windows"

	"github.com/kontext-security/kontext/internal/platform"
)

// stderrMissing reports a process with no error output to write to: kontextw.exe
// started by the logon task, which links for the GUI subsystem.
var stderrMissing = func() bool {
	handle := windows.Handle(os.Stderr.Fd())
	return handle == 0 || handle == windows.InvalidHandle
}

// redirectDaemonLog sends the daemon's error output to daemon.log in the user's
// local app data when there is nowhere else for it to go, so a daemon that stops
// at logon says why. A crash goes there too: the runtime writes it to the
// process's own error handle, not to os.Stderr. It returns a func that closes
// the log.
func redirectDaemonLog() func() {
	if !stderrMissing() {
		return func() {}
	}
	dir, err := platform.UserStateDir()
	if err != nil {
		return func() {}
	}
	f, err := openDaemonLog(dir)
	if err != nil {
		return func() {}
	}
	os.Stderr = f
	log.SetOutput(f)
	_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	return func() {
		_ = debug.SetCrashOutput(nil, debug.CrashOptions{})
		_ = f.Close()
	}
}
