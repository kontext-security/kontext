//go:build !windows

package main

import (
	"os/exec"
	"syscall"
	"testing"
)

func prepareDaemonHelper(*exec.Cmd) {}

func sendDaemonStop(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
}
