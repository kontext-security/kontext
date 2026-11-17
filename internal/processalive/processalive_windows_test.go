//go:build windows

package processalive

import (
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/windows"
)

// The liveness check tells a running process from one that has exited, and
// counts a process this user may not open as running.
func TestProcessAliveOnWindows(t *testing.T) {
	if !Alive(os.Getpid()) {
		t.Fatal("this process does not count as alive")
	}
	// The System process: there, and not to be opened by a standard user.
	if !Alive(4) {
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
	if Alive(pid) {
		t.Fatalf("pid %d of a child that has exited and been waited for counts as alive", pid)
	}
}

// A process that has ended but is still held open by someone else can still
// be opened (seen on Windows 11 on arm64); it does not count as alive.
func TestProcessAliveOnWindowsEndedButHeldOpen(t *testing.T) {
	child := exec.Command(os.Args[0], "-test.run=^$")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Wait() }()
	pid := child.Process.Pid
	held, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		t.Fatalf("open the child: %v", err)
	}
	defer windows.CloseHandle(held)
	if event, err := windows.WaitForSingleObject(held, 30000); err != nil || event != windows.WAIT_OBJECT_0 {
		t.Fatalf("the child did not end: %v, %v", event, err)
	}
	if Alive(pid) {
		t.Fatalf("pid %d of a child that has ended, still held open, counts as alive", pid)
	}
}
