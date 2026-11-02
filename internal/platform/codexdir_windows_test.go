package platform_test

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// wantCodexDir asks Windows for its folder, not the environment, so a filtered
// environment can't change what the test expects.
func wantCodexDir(t *testing.T) string {
	t.Helper()
	windowsDir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.VolumeName(windowsDir) + `\ProgramData\OpenAI\Codex`
}
