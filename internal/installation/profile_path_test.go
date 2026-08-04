package installation

import (
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/profile"
)

func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(profile.EnvRoot, "")
	return home
}

func TestUserPathFallsBackToLegacyWithoutActiveProfile(t *testing.T) {
	home := fakeHome(t)
	want := filepath.Join(home, "Library", "Application Support", "Kontext", "installation.json")
	if got := UserPath(); got != want {
		t.Fatalf("UserPath() = %q, want legacy %q", got, want)
	}
}

// Each profile carries its own identity: one Mac enrolled in two workspaces
// must not present the same installation id to both.
func TestUserPathIsPerProfile(t *testing.T) {
	home := fakeHome(t)
	for _, name := range []string{"prod", "staging"} {
		if _, err := profile.Create(name); err != nil {
			t.Fatal(err)
		}
	}
	base := filepath.Join(home, "Library", "Application Support", "Kontext", "profiles")

	if err := profile.SetActive("prod"); err != nil {
		t.Fatal(err)
	}
	prod := UserPath()
	if want := filepath.Join(base, "prod", "installation.json"); prod != want {
		t.Fatalf("UserPath() = %q, want %q", prod, want)
	}

	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}
	staging := UserPath()
	if want := filepath.Join(base, "staging", "installation.json"); staging != want {
		t.Fatalf("UserPath() = %q, want %q", staging, want)
	}

	if prod == staging {
		t.Fatal("UserPath() returned the same identity path for two profiles")
	}
}

// Distinct identity paths must actually yield distinct ids — the point of
// per-profile identity, not just per-profile filenames.
func TestEnsureFileGivesEachProfileItsOwnInstallationID(t *testing.T) {
	fakeHome(t)
	for _, name := range []string{"prod", "staging"} {
		if _, err := profile.Create(name); err != nil {
			t.Fatal(err)
		}
	}

	if err := profile.SetActive("prod"); err != nil {
		t.Fatal(err)
	}
	prod, err := EnsureFile(UserPath())
	if err != nil {
		t.Fatalf("EnsureFile() error = %v", err)
	}

	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}
	staging, err := EnsureFile(UserPath())
	if err != nil {
		t.Fatalf("EnsureFile() error = %v", err)
	}

	if prod.InstallationID == staging.InstallationID {
		t.Fatalf("both profiles got installation id %q", prod.InstallationID)
	}

	// Re-activating must return the SAME id, not mint a new one.
	if err := profile.SetActive("prod"); err != nil {
		t.Fatal(err)
	}
	again, err := EnsureFile(UserPath())
	if err != nil {
		t.Fatal(err)
	}
	if again.InstallationID != prod.InstallationID {
		t.Fatalf("switching back changed the installation id: %q -> %q", prod.InstallationID, again.InstallationID)
	}
}
