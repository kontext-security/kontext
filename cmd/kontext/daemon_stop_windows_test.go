//go:build windows

package main

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func prepareDaemonHelper(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

func sendDaemonStop(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid)); err != nil {
		if os.Getenv("GITHUB_ACTIONS") != "" {
			t.Fatalf("no console to send the event through: %v", err)
		}
		t.Skipf("no console to send the event through: %v", err)
	}
}
