//go:build !windows

package processalive

import (
	"errors"

	"golang.org/x/sys/unix"
)

// Signal 0 checks for the process without delivering anything; EPERM means
// it exists under another user.
func alive(pid int) bool {
	err := unix.Kill(pid, 0)
	return err == nil || errors.Is(err, unix.EPERM)
}
