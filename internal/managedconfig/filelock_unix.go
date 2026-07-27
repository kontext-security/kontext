//go:build !windows

package managedconfig

import (
	"os"

	"golang.org/x/sys/unix"
)

// WithWriteLock serializes cooperating writers of the managed config at path
// (`kontext setup` and the daemon's mode migration) through a sidecar lock
// file, so a read-verify-replace sequence cannot clobber a concurrent
// rewrite. The lock is advisory: only our own writers take it. MDM-pushed
// system configs are never rewritten by this code, so external writers are
// out of scope. Writers hold the lock for the duration of one small file
// write; blocking acquisition is fine.
func WithWriteLock(path string, fn func() error) error {
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
