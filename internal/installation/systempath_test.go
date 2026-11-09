package installation

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kontext-security/kontext/internal/platform"
)

// Without an override, an organization-managed daemon's identity is SystemPath:
// the folder macOS packages own, or on Windows the user's own state folder,
// since each user's daemon is its own installation there.
func TestPathFromEnvDefaultsToSystemPath(t *testing.T) {
	t.Setenv(EnvPath, "")
	want := DefaultPath
	if runtime.GOOS == "windows" {
		dir, err := platform.UserStateDir()
		if err != nil {
			t.Fatal(err)
		}
		want = filepath.Join(dir, "installation.json")
	}
	if got := SystemPath(); got != want {
		t.Fatalf("SystemPath() = %q, want %q", got, want)
	}
	if got := PathFromEnv(); got != want {
		t.Fatalf("PathFromEnv() = %q, want %q", got, want)
	}
}

// A path that couldn't be worked out is an error, not a file in the current folder.
func TestEmptyPathIsRefused(t *testing.T) {
	if _, err := LoadFile(""); err == nil {
		t.Error("LoadFile(\"\") succeeded")
	}
	if _, err := EnsureFile(""); err == nil {
		t.Error("EnsureFile(\"\") succeeded")
	}
}
