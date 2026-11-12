//go:build windows

package managedobserve

import (
	"os"
	"os/exec"
	"testing"
)

// The liveness check tells a running process from one that has exited, and
// counts a process this user may not open as running.
func TestProcessAliveOnWindows(t *testing.T) {
	if !pidAlive(os.Getpid()) {
		t.Fatal("this process does not count as alive")
	}
	// The System process: there, and not to be opened by a standard user.
	if !pidAlive(4) {
		t.Fatal("the System process does not count as alive")
	}
	child := exec.Command(os.Args[0], "-test.run=^$")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	pid := child.Process.Pid
	if err := child.Wait(); err != nil {
		t.Fatalf("the child did not exit cleanly: %v", err)
	}
	if pidAlive(pid) {
		t.Fatalf("pid %d of a child that has exited and been waited for counts as alive", pid)
	}
}
