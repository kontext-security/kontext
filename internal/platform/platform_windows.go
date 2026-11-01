package platform

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func SystemConfigDir() (string, error) {
	return programData("Kontext")
}

// UserStateDir follows LOCALAPPDATA, as os.UserCacheDir does, which keeps a
// test's redirected folder. A process started without the variable, or with a
// relative one, gets the known folder instead. That one follows USERPROFILE, so
// a relative profile is an error, not a path under the current directory.
func UserStateDir() (string, error) {
	if dir, err := os.UserCacheDir(); err == nil && filepath.IsAbs(dir) {
		return filepath.Join(dir, "Kontext"), nil
	}
	dir, err := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DONT_VERIFY)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("local app data %q is not absolute", dir)
	}
	return filepath.Join(dir, "Kontext"), nil
}

// ClaudeManagedDir is the fixed path Claude Code reads, whichever drive Windows
// is on.
func ClaudeManagedDir() (string, error) {
	return `C:\Program Files\ClaudeCode`, nil
}

// CodexSystemDir differs from what Codex asks Windows for only if ProgramData
// was moved, which the callers that write there have to consider.
func CodexSystemDir() (string, error) {
	return programData("OpenAI", "Codex")
}

// programData does not ask for FOLDERID_ProgramData. Windows stores that folder
// as %SystemDrive%\ProgramData and expands it from the process's environment,
// so a variable moves it, and without the variable the text comes back
// unexpanded. The drive of the Windows folder does not depend on the
// environment. A ProgramData moved elsewhere is not followed.
func programData(elem ...string) (string, error) {
	windowsDir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return "", err
	}
	return programDataOn(windowsDir, elem...), nil
}

func programDataOn(windowsDir string, elem ...string) string {
	root := filepath.VolumeName(windowsDir) + `\ProgramData`
	return filepath.Join(append([]string{root}, elem...)...)
}
