//go:build windows

package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

// stopProcess ends the process pid when it is the Kontext daemon, and waits
// for it to be gone. The pid comes from the daemon's status file, which can
// be stale, so the process is ended only if its program is named as the
// daemon's is (the CLI's own name does not count: a hook may have the pid); another program that got the same pid is left alone. A
// process that is not there any more is not an error.
//
// The daemon has no console on Windows and takes no signal, so this is an
// abrupt end: records it had queued and not yet written are lost.
func stopProcess(pid int) error {
	if pid == os.Getpid() {
		return nil // a stale pid that this very process got
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// No such process, or one this user may not end: the user's own
		// daemon can always be opened, so that one is not it.
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) || errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil
		}
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	path := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(path))
	if err := windows.QueryFullProcessImageName(handle, 0, &path[0], &size); err != nil {
		return fmt.Errorf("name the program of process %d: %w", pid, err)
	}
	if name := filepath.Base(windows.UTF16ToString(path[:size])); !isDaemonProgram(name) {
		return nil // the pid belongs to another program now
	}
	if err := windows.TerminateProcess(handle, 1); err != nil {
		// Access denied is also what a process that has just exited answers.
		if event, waitErr := windows.WaitForSingleObject(handle, 0); waitErr == nil && event == windows.WAIT_OBJECT_0 {
			return nil
		}
		return fmt.Errorf("end process %d: %w", pid, err)
	}
	event, err := windows.WaitForSingleObject(handle, uint32((10 * time.Second).Milliseconds()))
	if err != nil {
		return fmt.Errorf("wait for process %d: %w", pid, err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("process %d did not end within 10 s", pid)
	}
	return nil
}

func isDaemonProgram(name string) bool {
	return strings.EqualFold(name, windowsDaemonName)
}
