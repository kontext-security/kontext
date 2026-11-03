package codexmanaged

import (
	"encoding/base64"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
)

// The forced preferences MDM writes as binary property lists come out
// through plutil, this user's before the Mac's, dates and all.
func TestManagedPreferencesAreReadAsMDMWritesThem(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	_, codexHome, _ := adminLayers(t)
	managedPreferences = readManagedPreferences
	dir := t.TempDir()
	previous := managedPreferencesDir
	t.Cleanup(func() { managedPreferencesDir = previous })
	managedPreferencesDir = dir
	if preferences, err := readManagedPreferences(); err != nil || len(preferences) != 0 {
		t.Fatalf("readManagedPreferences without profiles = %v, %v", preferences, err)
	}

	plist := func(path string, edits ...[]string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		for _, edit := range append([][]string{{"-create", "binary1"}}, edits...) {
			if out, err := exec.Command("/usr/bin/plutil", append(edit, path)...).CombinedOutput(); err != nil {
				t.Fatalf("plutil %v: %v\n%s", edit, err, out)
			}
		}
	}
	requirements := base64.StdEncoding.EncodeToString([]byte("model_provider = \"corp\"\n"))
	plist(filepath.Join(dir, codexPreferenceDomain+".plist"),
		[]string{"-insert", "requirements_toml_base64", "-string", requirements},
		[]string{"-insert", "PayloadInstalled", "-date", "2026-11-03T12:00:00Z"})
	plist(filepath.Join(dir, current.Username, codexPreferenceDomain+".plist"),
		[]string{"-insert", "check_for_update_on_startup", "-bool", "false"})
	preferences, err := readManagedPreferences()
	if err != nil || len(preferences) != 2 || len(preferences[0]) != 0 || preferences[1]["requirements_toml_base64"] != requirements {
		t.Fatalf("readManagedPreferences = %v, %v", preferences, err)
	}
	if blocker, err := AdminRouteBlocker(codexHome); err != nil || blocker != "the managed preference com.openai.codex requirements_toml_base64 sets model_provider" {
		t.Fatalf("AdminRouteBlocker = %q, %v", blocker, err)
	}
}
