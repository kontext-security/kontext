//go:build !windows

package managedobserve

import (
	"os/exec"
	"syscall"
	"testing"
)

func prepareStopHelper(*exec.Cmd) {}

func sendStopSignal(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
}
