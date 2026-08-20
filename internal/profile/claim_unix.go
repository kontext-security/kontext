//go:build !windows

package profile

import (
	"errors"

	"golang.org/x/sys/unix"
)

// pidAlive reports whether pid names a running process. Signal 0 performs the
// existence check without delivering anything; EPERM still means the process
// exists, just under another user.
func pidAlive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}
