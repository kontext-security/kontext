//go:build !windows

package managedobserve

import (
	"os"
	"syscall"
)

// daemonAlive reports whether pid names a running process this user may
// signal. A process of another user counts as gone: the agent runs as this
// user, and a status file that outlived a reboot can name a pid that now
// belongs to a system process.
func daemonAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
