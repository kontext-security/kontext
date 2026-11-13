//go:build windows

package setup

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestHelperSleeps is the child of the tests below: this test binary, started
// under another name, that just stays alive.
func TestHelperSleeps(t *testing.T) {
	if os.Getenv("KONTEXT_TEST_SLEEP") != "1" {
		t.Skip("a helper for TestStopProcess")
	}
	time.Sleep(2 * time.Minute)
}

func startSleeper(t *testing.T, name string) *exec.Cmd {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(t.TempDir(), name)
	source, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(program, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(program, "-test.run=^TestHelperSleeps$")
	cmd.Env = append(os.Environ(), "KONTEXT_TEST_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	return cmd
}

func exited(cmd *exec.Cmd, within time.Duration) bool {
	done := make(chan struct{})
	go func() { _, _ = cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(within):
		return false
	}
}

// The daemon's process is ended and gone when stopProcess returns. A process
// of another program that has the pid is left alone, since the pid comes from
// a status file that can be stale.
func TestStopProcessEndsTheDaemonAndNothingElse(t *testing.T) {
	daemon := startSleeper(t, windowsDaemonName)
	if err := stopProcess(daemon.Process.Pid); err != nil {
		t.Fatalf("stopProcess(daemon) = %v", err)
	}
	if !exited(daemon, 5*time.Second) {
		t.Fatal("the daemon's process is still running after stopProcess returned")
	}

	// The CLI's own program is not the daemon either: a hook may hold the pid.
	cli := startSleeper(t, "kontext.exe")
	if err := stopProcess(cli.Process.Pid); err != nil {
		t.Fatalf("stopProcess(the CLI) = %v", err)
	}
	if exited(cli, 500*time.Millisecond) {
		t.Fatal("stopProcess ended a CLI process")
	}
	if err := stopProcess(os.Getpid()); err != nil {
		t.Fatalf("stopProcess(this process) = %v", err)
	}

	other := startSleeper(t, "notepad-like.exe")
	if err := stopProcess(other.Process.Pid); err != nil {
		t.Fatalf("stopProcess(another program) = %v", err)
	}
	if exited(other, 500*time.Millisecond) {
		t.Fatal("stopProcess ended a process that is not the daemon")
	}

	// A process this user may not open (the System process) is not the
	// daemon: no error.
	if err := stopProcess(4); err != nil {
		t.Fatalf("stopProcess(the System process) = %v", err)
	}
}
