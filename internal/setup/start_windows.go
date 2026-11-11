//go:build windows

package setup

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// startDetached starts program on its own: no console, not in this process's
// group, and not waited for, so it outlives the setup run that started it. It
// gets no standard handles at all, as a program Explorer starts at sign-in
// has none: the daemon writes its log file only when it has no error output,
// and with the null device for one (what os/exec gives) it logged nowhere.
func startDetached(program string, args ...string) error {
	_, handle, err := syscall.StartProcess(program, append([]string{program}, args...), &syscall.ProcAttr{
		Env:   os.Environ(),
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
