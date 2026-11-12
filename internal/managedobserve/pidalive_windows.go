//go:build windows

package managedobserve

import (
	"errors"

	"golang.org/x/sys/windows"
)

// processAlive reports whether a process with this pid is running. The unix
// idiom, a signal 0, says "dead" for every pid on Windows, so the process is
// opened and asked: one that has exited is signalled, a running one is not.
// A process this user may not open exists all the same.
func processAlive(pid int) bool {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer windows.CloseHandle(handle)
	event, err := windows.WaitForSingleObject(handle, 0)
	return err == nil && event == uint32(windows.WAIT_TIMEOUT)
}
