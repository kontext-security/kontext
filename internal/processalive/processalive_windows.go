//go:build windows

package processalive

import (
	"errors"

	"golang.org/x/sys/windows"
)

// Windows has no signal 0, so the process is opened and asked: one that has
// ended is signalled, also while something else still holds it open, and a
// running one is not. A process this user may not open exists all the same.
func alive(pid int) bool {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_ACCESS_DENIED)
	}
	defer windows.CloseHandle(handle)
	event, err := windows.WaitForSingleObject(handle, 0)
	return err == nil && event == uint32(windows.WAIT_TIMEOUT)
}
