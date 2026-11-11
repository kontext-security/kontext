//go:build windows

package setup

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestHelperReportsItsStderr is the child of the test below: it writes down
// whether it was started with an error output.
func TestHelperReportsItsStderr(t *testing.T) {
	out := os.Getenv("KONTEXT_TEST_STDERR_REPORT")
	if out == "" {
		t.Skip("a helper for TestStartDetachedGivesNoErrorOutput")
	}
	handle, err := windows.GetStdHandle(windows.STD_ERROR_HANDLE)
	report := "present"
	if err != nil || handle == 0 || handle == windows.InvalidHandle {
		report = "missing"
	}
	if err := os.WriteFile(out, []byte(report), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The daemon writes its log file only when it has no error output. One that
// setup starts must be in that state, as one started at sign-in is.
func TestStartDetachedGivesNoErrorOutput(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The control: started the way os/exec does it, the helper has an error
	// output (the null device), which is what kept the daemon from its log.
	control := filepath.Join(t.TempDir(), "control")
	t.Setenv("KONTEXT_TEST_STDERR_REPORT", control)
	if err := exec.Command(self, "-test.run=^TestHelperReportsItsStderr$").Run(); err != nil {
		t.Fatalf("the control run failed: %v", err)
	}
	if got, _ := os.ReadFile(control); string(got) != "present" {
		t.Fatalf("the control's error output is %q, want present", got)
	}

	report := filepath.Join(t.TempDir(), "stderr")
	t.Setenv("KONTEXT_TEST_STDERR_REPORT", report)
	if err := startDetached(self, "-test.run=^TestHelperReportsItsStderr$"); err != nil {
		t.Fatalf("startDetached() = %v", err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		got, err := os.ReadFile(report)
		if err == nil && len(got) > 0 {
			if string(got) != "missing" {
				t.Fatalf("the started program's error output is %s, want missing", got)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the started program wrote no report: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
