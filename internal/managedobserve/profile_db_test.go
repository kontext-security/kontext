package managedobserve

import (
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/managedstream"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

func fakeProfileHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(profile.EnvRoot, "")
	t.Setenv(envDBPath, "")
	return home
}

func TestDefaultDBPathFallsBackToLegacyWithoutActiveProfile(t *testing.T) {
	fakeProfileHome(t)
	if got, want := DefaultDBPath(), LegacyDBPath(); got != want {
		t.Fatalf("DefaultDBPath() = %q, want legacy %q", got, want)
	}
}

// The explicit env override outranks the active profile: the daemon's hidden
// --db/env seam must stay usable for local debugging.
func TestDefaultDBPathHonorsEnvOverrideOverActiveProfile(t *testing.T) {
	fakeProfileHome(t)
	if _, err := profile.Create("staging"); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}
	override := filepath.Join(t.TempDir(), "custom.db")
	t.Setenv(envDBPath, override)
	if got := DefaultDBPath(); got != override {
		t.Fatalf("DefaultDBPath() = %q, want override %q", got, override)
	}
}

// This is the export fence: separate databases per profile mean the stream
// cursor (derived from the database's directory) is separate too, so a backlog
// captured for one workspace cannot be flushed to another.
func TestDefaultDBPathAndStreamCursorAreFencedPerProfile(t *testing.T) {
	fakeProfileHome(t)
	for _, name := range []string{"prod", "staging"} {
		if _, err := profile.Create(name); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("KONTEXT_MANAGED_STREAM_STATE", "")

	if err := profile.SetActive("prod"); err != nil {
		t.Fatal(err)
	}
	prodDB := DefaultDBPath()
	prodCursor := managedstream.DefaultStatePathForDB(prodDB)

	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}
	stagingDB := DefaultDBPath()
	stagingCursor := managedstream.DefaultStatePathForDB(stagingDB)

	if prodDB == stagingDB {
		t.Fatalf("both profiles share ledger database %q", prodDB)
	}
	if prodCursor == stagingCursor {
		t.Fatalf("both profiles share export cursor %q", prodCursor)
	}
	if filepath.Dir(prodCursor) != filepath.Dir(prodDB) {
		t.Fatalf("cursor %q does not sit beside its database %q", prodCursor, prodDB)
	}
}
