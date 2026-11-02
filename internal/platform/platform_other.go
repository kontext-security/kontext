//go:build !windows

package platform

import (
	"os"
	"path/filepath"
	"runtime"
)

// SystemConfigDir is the same on Linux as on macOS until the Linux port moves it.
func SystemConfigDir() (string, error) {
	return "/Library/Application Support/Kontext", nil
}

func UserStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "Kontext"), nil
}

// ClaudeManagedDir is where Claude Code reads its managed settings.
func ClaudeManagedDir() string {
	return claudeManagedDirOn(runtime.GOOS)
}

func claudeManagedDirOn(goos string) string {
	if goos == "linux" {
		return "/etc/claude-code"
	}
	return "/Library/Application Support/ClaudeCode"
}

func CodexSystemDir() (string, error) {
	return "/etc/codex", nil
}
