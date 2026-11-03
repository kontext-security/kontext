//go:build windows

package instancelock

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

const openNoFollow = windows.O_FILE_FLAG_OPEN_REPARSE_POINT

// lockOffsetHigh puts the locked byte far past the PID: a locked range can't
// be read, even by the process asking who holds the lock.
const lockOffsetHigh = 0x7fffffff

func tryLock(file *os.File) (bool, error) {
	overlapped := windows.Overlapped{OffsetHigh: lockOffsetHigh}
	err := windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped,
	)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return false, nil
	}
	return err == nil, err
}
