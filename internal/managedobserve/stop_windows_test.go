//go:build windows

package managedobserve

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func prepareStopHelper(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

// A console event is what Windows has for a polite stop. Stop-Process -Force and
// a task's End are TerminateProcess, which a process can't see.
func sendStopSignal(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid)); err != nil {
		// CI shouldn't go green without having sent anything.
		if os.Getenv("GITHUB_ACTIONS") != "" {
			t.Fatalf("no console to send the event through: %v", err)
		}
		t.Skipf("no console to send the event through: %v", err)
	}
}
