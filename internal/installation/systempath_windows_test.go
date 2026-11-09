package installation

import (
	"os"
	"path/filepath"
	"testing"
)

// Each user's daemon creates its own identity under its own local app data, so
// a second user on the machine doesn't meet a file the first one owns.
func TestSystemPathIsPerUserOnWindows(t *testing.T) {
	t.Setenv(EnvPath, "")
	local := t.TempDir()
	t.Setenv("LOCALAPPDATA", local)
	want := filepath.Join(local, "Kontext", "installation.json")
	if got := PathFromEnv(); got != want {
		t.Fatalf("PathFromEnv() = %q, want %q", got, want)
	}
	created, err := EnsureFile(want)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(want)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != created {
		t.Fatalf("loaded %+v, created %+v", loaded, created)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("no identity at %s: %v", want, err)
	}
}
