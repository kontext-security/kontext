//go:build windows

package autostart

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The helper is this test binary under another name. It cannot be told
// through the environment that it is the helper: Start does not pass the
// caller's environment on, which is one of the things under test.
const (
	helperName     = "kx-start-helper.exe"
	callerVariable = "KX_TEST_ONLY_IN_THE_CALLER"
)

// TestHelperReportsHowItWasStarted is the child of the test below: it writes
// down, beside its own program, whether it has an error output and whether
// it sees the caller's variable.
func TestHelperReportsHowItWasStarted(t *testing.T) {
	self, err := os.Executable()
	if err != nil || filepath.Base(self) != helperName {
		t.Skip("a helper for TestStartGivesNoErrorOutputAndTheUsersEnvironment")
	}
	report := "stderr=present"
	if handle, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE); err != nil || handle == 0 || handle == windows.InvalidHandle {
		report = "stderr=missing"
	}
	if os.Getenv(callerVariable) != "" {
		report += " caller-environment=inherited"
	} else {
		report += " caller-environment=absent"
	}
	if err := os.WriteFile(self+".report", []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
}

func copyOfThisTestBinary(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	helper := filepath.Join(t.TempDir(), helperName)
	target, err := os.OpenFile(helper, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	return helper
}

func waitForReport(t *testing.T, helper string) string {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		got, err := os.ReadFile(helper + ".report")
		if err == nil && len(got) > 0 {
			return string(got)
		}
		if time.Now().After(deadline) {
			t.Fatalf("the started program wrote no report: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The daemon writes its log file only when it has no error output, and it
// outlives whatever started it. So a started program has no error output, as
// one started at sign-in has none, and the user's environment, not the
// caller's.
func TestStartGivesNoErrorOutputAndTheUsersEnvironment(t *testing.T) {
	t.Setenv(callerVariable, "1")
	const run = "-test.run=^TestHelperReportsHowItWasStarted$"

	// The control: started the way os/exec does it, the helper has an error
	// output (the null device) and the caller's environment.
	control := copyOfThisTestBinary(t)
	if err := exec.Command(control, run).Run(); err != nil {
		t.Fatalf("the control run failed: %v", err)
	}
	if got := waitForReport(t, control); got != "stderr=present caller-environment=inherited" {
		t.Fatalf("the control reports %q", got)
	}

	helper := copyOfThisTestBinary(t)
	if err := Start(helper, run); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	if got := waitForReport(t, helper); got != "stderr=missing caller-environment=absent" {
		t.Fatalf("the started program reports %q", got)
	}
}
