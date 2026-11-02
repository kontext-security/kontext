//go:build !windows

package platform

import "testing"

// CI runs its Go tests off Windows on Linux only, so this checks the macOS row
// there too: a change to the path Claude Code reads on a Mac can't pass unseen.
func TestClaudeManagedDirOn(t *testing.T) {
	for goos, want := range map[string]string{
		"darwin": "/Library/Application Support/ClaudeCode",
		"linux":  "/etc/claude-code",
	} {
		if got := claudeManagedDirOn(goos); got != want {
			t.Errorf("claudeManagedDirOn(%q) = %q, want %q", goos, got, want)
		}
	}
}
