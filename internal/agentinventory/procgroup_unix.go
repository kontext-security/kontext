//go:build unix

package agentinventory

import (
	"os/exec"
	"syscall"
)

// ownProcessGroup runs cmd in its own process group and kills the whole group
// on cancel, so a timed-out CLI cannot leave children behind.
func ownProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
