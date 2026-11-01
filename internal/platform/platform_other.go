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

// ClaudeManagedDir on Linux is where claudemanaged's managed settings point
// today. Its drop-in and mcpconfig's managed MCP file still name the macOS
// folder there, so moving those changes what Kontext writes and reads on Linux.
func ClaudeManagedDir() (string, error) {
	if runtime.GOOS == "linux" {
		return "/etc/claude-code", nil
	}
	return "/Library/Application Support/ClaudeCode", nil
}

func CodexSystemDir() (string, error) {
	return "/etc/codex", nil
}
