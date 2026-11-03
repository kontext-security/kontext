package codexmanaged

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"time"
)

// managedPreferencesDir is where macOS keeps the preferences MDM profiles
// force, for the Mac and, in a folder per user, for each user: the forced
// values Codex reads through CFPreferences.
var managedPreferencesDir = "/Library/Managed Preferences"

// readManagedPreferences reads the strings MDM profiles force in Codex's
// preference domain, this user's before the Mac's.
func readManagedPreferences() ([]map[string]string, error) {
	paths := []string{filepath.Join(managedPreferencesDir, codexPreferenceDomain+".plist")}
	if current, err := user.Current(); err == nil {
		paths = append([]string{filepath.Join(managedPreferencesDir, current.Username, codexPreferenceDomain+".plist")}, paths...)
	}
	var preferences []map[string]string
	for _, path := range paths {
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		// MDM writes binary property lists, which plutil turns into XML; JSON
		// cannot hold every value they may carry.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		data, err := exec.CommandContext(ctx, "/usr/bin/plutil", "-convert", "xml1", "-o", "-", path).Output()
		cancel()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		values, err := plistStrings(data)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		preferences = append(preferences, values)
	}
	return preferences, nil
}
