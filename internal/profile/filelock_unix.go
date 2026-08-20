//go:build !windows

package profile

import (
	"os"

	"golang.org/x/sys/unix"
)

// withPointerLock serializes every writer of the active pointer at path
// through a sidecar lock file, so a read-then-write sequence — SetActive's
// existence check, CompareAndSetActive's comparison — is atomic against the
// other writers rather than an interleavable check. The lock is advisory:
// only our own writers take it, and each holds it for one small file write,
// so blocking acquisition is fine.
func withPointerLock(path string, fn func() error) error {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	}()
	return fn()
}
