//go:build !windows

package managedobserve

import (
	"os"
	"syscall"
)

// processAlive reports whether a process with this pid is running.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
