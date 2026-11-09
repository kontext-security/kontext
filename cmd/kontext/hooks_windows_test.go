package main

import (
	"io"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
	"golang.org/x/sys/windows"
)

func TestHooksPrivilegedFollowsTokenElevation(t *testing.T) {
	if got, want := hooksPrivileged(), windows.GetCurrentProcessToken().IsElevated(); got != want {
		t.Fatalf("hooksPrivileged() = %v, want the token's elevation %v", got, want)
	}
}

// A machine-wide hook names a binary only when told which one: Windows has no
// default install folder yet.
func TestHooksWindowsSystemInstallNeedsBinary(t *testing.T) {
	old := hooksPrivileged
	hooksPrivileged = func() bool { return true }
	t.Cleanup(func() { hooksPrivileged = old })
	hermetic.SetHome(t, t.TempDir())
	cmd := hooksCmd()
	cmd.SetArgs([]string{"install", "--scope", "system"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "--binary") {
		t.Fatalf("err = %v, want a --binary error", err)
	}
}
