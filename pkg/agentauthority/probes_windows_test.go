//go:build windows

package agentauthority

import (
	"os/user"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// Go's own answer for a user id on Windows is -1, which names nobody.
func TestProbeEnvironmentNamesTheWindowsUser(t *testing.T) {
	e := ProbeEnvironment()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	// user.Current gives the SID as text; its last part is the uid reported.
	want, err := strconv.Atoi(current.Uid[strings.LastIndex(current.Uid, "-")+1:])
	if err != nil {
		t.Fatalf("SID %q: %v", current.Uid, err)
	}
	if e.UID != want || e.UID < 0 {
		t.Errorf("uid = %d, want %d, the last part of %s", e.UID, want, current.Uid)
	}
	if elevated := windows.GetCurrentProcessToken().IsElevated(); e.Root != elevated {
		t.Errorf("root = %v, want %v as the process is elevated or not", e.Root, elevated)
	}
	if e.Root && !e.Admin {
		t.Error("an elevated process whose account is not an administrator")
	}
	if e.Container {
		t.Error("container = true")
	}
	t.Logf("environment: %+v", e)
}
