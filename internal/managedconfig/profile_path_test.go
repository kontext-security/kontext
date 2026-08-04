package managedconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/profile"
)

// fakeHome points both the legacy path and the profile root at a temp home, as
// they share it in a real install.
func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(profile.EnvRoot, "")
	return home
}

func kontextDir(home string) string {
	return filepath.Join(home, "Library", "Application Support", "Kontext")
}

// An install that predates profiles has no pointer and must resolve exactly the
// path it always did.
func TestUserPathFallsBackToLegacyWithoutActiveProfile(t *testing.T) {
	home := fakeHome(t)
	want := filepath.Join(kontextDir(home), "managed.json")
	if got := UserPath(); got != want {
		t.Fatalf("UserPath() = %q, want legacy %q", got, want)
	}
	if got := LegacyUserPath(); got != want {
		t.Fatalf("LegacyUserPath() = %q, want %q", got, want)
	}
}

func TestUserPathResolvesActiveProfile(t *testing.T) {
	home := fakeHome(t)
	if _, err := profile.Create("staging"); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(kontextDir(home), "profiles", "staging", "managed.json")
	if got := UserPath(); got != want {
		t.Fatalf("UserPath() = %q, want %q", got, want)
	}
}

// A corrupt pointer falls back to the legacy path, which after migration does
// not exist — so Load fails closed with ErrNotManaged rather than streaming
// through some other profile's credentials.
func TestUserPathWithCorruptPointerFailsClosed(t *testing.T) {
	home := fakeHome(t)
	root := kontextDir(home)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "active"), []byte("../../elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	legacy := filepath.Join(root, "managed.json")
	if got := UserPath(); got != legacy {
		t.Fatalf("UserPath() = %q, want legacy %q", got, legacy)
	}
	// Migration moved the legacy config away, so nothing loads.
	t.Setenv(EnvPath, "")
	systemPath = filepath.Join(t.TempDir(), "absent-system-managed.json")
	t.Cleanup(func() { systemPath = DefaultPath })
	if _, err := Load(); err == nil {
		t.Fatal("Load() with a corrupt pointer and no legacy config = nil error, want failure")
	}
}

// An MDM config still wins over any profile: a self-serve profile must not be
// able to re-point an organization-managed Mac.
func TestSystemScopeStillWinsOverActiveProfile(t *testing.T) {
	fakeHome(t)
	if _, err := profile.Create("staging"); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}
	system := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(system, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvPath, "")
	systemPath = system
	t.Cleanup(func() { systemPath = DefaultPath })

	path, scope := ResolvePath()
	if scope != ScopeSystem {
		t.Fatalf("ResolvePath() scope = %q, want %q", scope, ScopeSystem)
	}
	if path != system {
		t.Fatalf("ResolvePath() = %q, want system %q", path, system)
	}
}
