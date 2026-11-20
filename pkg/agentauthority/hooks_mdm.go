package agentauthority

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"
)

// managedPreferences is where macOS keeps the preferences MDM profiles force,
// for the Mac and, in a folder per user, for each user.
var managedPreferences = "/Library/Managed Preferences"

const claudePreferenceDomain = "com.anthropic.claudecode"

// claudeMDMPolicy reports whether an MDM profile forces Claude Code settings
// on this Mac, by the profile file's presence alone.
func claudeMDMPolicy() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	paths := []string{filepath.Join(managedPreferences, claudePreferenceDomain+".plist")}
	if current, err := user.Current(); err == nil {
		paths = append(paths, filepath.Join(managedPreferences, current.Username, claudePreferenceDomain+".plist"))
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}
