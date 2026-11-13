//go:build windows

package autostart

import (
	"fmt"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// Start starts program on its own: no console, not in this process's
// group, and not waited for, so it outlives the setup run that started it. It
// gets no standard handles at all, as a program Explorer starts at sign-in
// has none: the daemon writes its log file only when it has no error output,
// and with the null device for one (what os/exec gives) it logged nowhere.
//
// It gets the user's own environment, not the caller's, again as at sign-in:
// the daemon outlives the shell or the agent session that started it, and
// must not carry that one's variables into every later session.
func Start(program string, args ...string) error {
	env, err := windows.GetCurrentProcessToken().Environ(false)
	if err != nil {
		return fmt.Errorf("read the user's environment: %w", err)
	}
	_, handle, err := syscall.StartProcess(program, append([]string{program}, args...), &syscall.ProcAttr{
		// Its own folder, so it does not keep the caller's open.
		Dir:   filepath.Dir(program),
		Env:   env,
		Files: []uintptr{0, 0, 0},
		Sys: &syscall.SysProcAttr{
			HideWindow:    true,
			CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
		},
	})
	if err != nil {
		return err
	}
	return syscall.CloseHandle(syscall.Handle(handle))
}
