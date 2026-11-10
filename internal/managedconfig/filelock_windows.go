//go:build windows

package managedconfig

import (
	"os"

	"golang.org/x/sys/windows"
)

// WithWriteLock serializes cooperating writers of the managed config at path
// through a sidecar lock file, as filelock_unix.go does with flock. LockFileEx
// waits for the lock, and the lock is per handle, so it also holds between
// goroutines of one process.
func WithWriteLock(path string, fn func() error) error {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	var overlapped windows.Overlapped
	handle := windows.Handle(lock.Fd())
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		return err
	}
	defer func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
	}()
	return fn()
}
