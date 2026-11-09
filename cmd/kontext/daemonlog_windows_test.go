package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Started by the logon task, kontextw.exe has no error output, so what the
// daemon would print goes to a log in the user's local app data instead.
func TestDaemonWithoutErrorOutputLogsToAFile(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	stderr, missing, logOutput := os.Stderr, stderrMissing, log.Writer()
	t.Cleanup(func() {
		os.Stderr, stderrMissing = stderr, missing
		log.SetOutput(logOutput) // Later tests mustn't log to the closed file.
	})
	stderrMissing = func() bool { return true }

	closeLog := redirectDaemonLog()
	fmt.Fprintln(os.Stderr, "kx-daemon-log-probe")
	closeLog()
	os.Stderr = stderr

	data, err := os.ReadFile(filepath.Join(local, "Kontext", "daemon.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "kx-daemon-log-probe") {
		t.Fatalf("log = %q", data)
	}
}

// With error output connected, as from a terminal or a test, nothing changes.
func TestDaemonWithErrorOutputKeepsIt(t *testing.T) {
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	missing := stderrMissing
	t.Cleanup(func() { stderrMissing = missing })
	stderrMissing = func() bool { return false }
	before := os.Stderr

	redirectDaemonLog()()
	if os.Stderr != before {
		t.Fatal("stderr was replaced")
	}
	if _, err := os.Stat(filepath.Join(local, "Kontext", "daemon.log")); !os.IsNotExist(err) {
		t.Fatalf("a log was created: %v", err)
	}
}

// A crash in the daemon lands in its log: the runtime writes it to the process's
// error handle, which kontextw.exe doesn't have. The test runs itself again to
// crash there.
func TestDaemonCrashLandsInTheLog(t *testing.T) {
	if os.Getenv("KX_DAEMON_CRASH_PROBE") == "1" {
		stderrMissing = func() bool { return true }
		_ = redirectDaemonLog()
		panic("kx-daemon-crash-probe")
	}
	local := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDaemonCrashLandsInTheLog$")
	cmd.Env = append(os.Environ(), "KX_DAEMON_CRASH_PROBE=1", "LOCALAPPDATA="+local)
	if err := cmd.Run(); err == nil {
		t.Fatal("the probe didn't crash")
	}
	data, err := os.ReadFile(filepath.Join(local, "Kontext", "daemon.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "panic: kx-daemon-crash-probe") {
		t.Fatalf("log = %q", data)
	}
}
