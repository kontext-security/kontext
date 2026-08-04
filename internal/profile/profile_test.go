package profile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func withRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv(EnvRoot, root)
	return root
}

func TestValidateNameAcceptsSimpleNames(t *testing.T) {
	for _, name := range []string{"default", "prod", "staging", "acme-dev", "wk_2", "a", "0"} {
		if err := ValidateName(name); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", name, err)
		}
	}
}

// A profile name becomes a path segment and a keychain service-name suffix, so
// the validator is the only thing standing between a hand-written name and a
// write outside the profile root.
func TestValidateNameRejectsTraversalAndSeparators(t *testing.T) {
	for _, name := range []string{
		"", ".", "..", "../etc", "a/b", `a\b`, "/abs", "with space", "UPPER",
		"trailing/", "-leading", "_leading", "a.b", "hasan@kontext", "naïve",
		"thisnameisverylongandexceedsthirtytwochars",
	} {
		if err := ValidateName(name); err == nil {
			t.Errorf("ValidateName(%q) = nil, want error", name)
		}
	}
}

func TestActiveNameReportsErrNoActiveWhenPointerAbsent(t *testing.T) {
	withRoot(t)
	if _, err := ActiveName(); !errors.Is(err, ErrNoActive) {
		t.Fatalf("ActiveName() error = %v, want ErrNoActive", err)
	}
}

// An unreadable or hostile pointer must surface, never degrade to the legacy
// paths — that would silently stream one profile's events using another
// profile's credentials.
func TestActiveNameRejectsUnusablePointer(t *testing.T) {
	for _, contents := range []string{"", "   \n", "../../elsewhere\n", "Prod\n", "a b\n"} {
		root := withRoot(t)
		if err := os.WriteFile(filepath.Join(root, activeFileName), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		name, err := ActiveName()
		if err == nil {
			t.Errorf("ActiveName() with pointer %q = %q, want error", contents, name)
			continue
		}
		if errors.Is(err, ErrNoActive) {
			t.Errorf("ActiveName() with pointer %q = ErrNoActive, want a hard error", contents)
		}
	}
}

func TestCreateSetActiveRoundTrip(t *testing.T) {
	withRoot(t)
	dir, err := Create("staging")
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("Create() did not make a directory: %v", err)
	}
	if err := SetActive("staging"); err != nil {
		t.Fatalf("SetActive() error = %v", err)
	}
	name, err := ActiveName()
	if err != nil {
		t.Fatalf("ActiveName() error = %v", err)
	}
	if name != "staging" {
		t.Fatalf("ActiveName() = %q, want %q", name, "staging")
	}
	activeDir, err := ActiveDir()
	if err != nil {
		t.Fatalf("ActiveDir() error = %v", err)
	}
	if activeDir != dir {
		t.Fatalf("ActiveDir() = %q, want %q", activeDir, dir)
	}
}

func TestCreateRejectsDuplicate(t *testing.T) {
	withRoot(t)
	if _, err := Create("prod"); err != nil {
		t.Fatal(err)
	}
	if _, err := Create("prod"); !errors.Is(err, ErrExists) {
		t.Fatalf("Create() second call error = %v, want ErrExists", err)
	}
}

// Pointing at a profile that does not exist would leave the daemon resolving a
// config path with nothing behind it.
func TestSetActiveRequiresExistingProfile(t *testing.T) {
	withRoot(t)
	if err := SetActive("ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SetActive() error = %v, want ErrNotFound", err)
	}
}

func TestListReturnsNilBeforeAnyProfileExists(t *testing.T) {
	withRoot(t)
	names, err := List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("List() = %v, want empty", names)
	}
}

func TestListSkipsNonProfileEntries(t *testing.T) {
	root := withRoot(t)
	for _, name := range []string{"prod", "staging"} {
		if _, err := Create(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, profilesDirName, "Not A Profile"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, profilesDirName, "stray.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	names, err := List()
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	want := []string{"prod", "staging"}
	if len(names) != len(want) {
		t.Fatalf("List() = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("List() = %v, want %v", names, want)
		}
	}
}

func TestRemoveRefusesActiveProfile(t *testing.T) {
	withRoot(t)
	if _, err := Create("prod"); err != nil {
		t.Fatal(err)
	}
	if err := SetActive("prod"); err != nil {
		t.Fatal(err)
	}
	if err := Remove("prod"); err == nil {
		t.Fatal("Remove() on the active profile = nil, want error")
	}
	exists, err := Exists("prod")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("Remove() deleted the active profile after refusing")
	}
}

func TestRemoveDeletesInactiveProfile(t *testing.T) {
	withRoot(t)
	for _, name := range []string{"prod", "staging"} {
		if _, err := Create(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := SetActive("prod"); err != nil {
		t.Fatal(err)
	}
	if err := Remove("staging"); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	exists, err := Exists("staging")
	if err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("Remove() left the profile directory behind")
	}
}

func TestClearActiveReturnsToLegacyResolution(t *testing.T) {
	withRoot(t)
	if _, err := Create("prod"); err != nil {
		t.Fatal(err)
	}
	if err := SetActive("prod"); err != nil {
		t.Fatal(err)
	}
	if err := ClearActive(); err != nil {
		t.Fatalf("ClearActive() error = %v", err)
	}
	if _, err := ActiveName(); !errors.Is(err, ErrNoActive) {
		t.Fatalf("ActiveName() after ClearActive = %v, want ErrNoActive", err)
	}
	// Idempotent: uninstall may run twice.
	if err := ClearActive(); err != nil {
		t.Fatalf("ClearActive() second call error = %v", err)
	}
}

func TestProfileScopedPaths(t *testing.T) {
	root := withRoot(t)
	base := filepath.Join(root, profilesDirName, "staging")

	config, err := ManagedConfigPath("staging")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, ManagedConfigFile); config != want {
		t.Errorf("ManagedConfigPath() = %q, want %q", config, want)
	}

	identity, err := InstallationPath("staging")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, InstallationFile); identity != want {
		t.Errorf("InstallationPath() = %q, want %q", identity, want)
	}

	db, err := DBPath("staging")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, ManagedObserveDir, ManagedObserveDB); db != want {
		t.Errorf("DBPath() = %q, want %q", db, want)
	}
}

func TestPathHelpersRejectInvalidNames(t *testing.T) {
	withRoot(t)
	if _, err := ManagedConfigPath("../escape"); err == nil {
		t.Error("ManagedConfigPath() with traversal = nil, want error")
	}
	if _, err := InstallationPath("../escape"); err == nil {
		t.Error("InstallationPath() with traversal = nil, want error")
	}
	if _, err := DBPath("../escape"); err == nil {
		t.Error("DBPath() with traversal = nil, want error")
	}
	if name := KeychainItemName("../escape"); name != "" {
		t.Errorf("KeychainItemName() with traversal = %q, want empty", name)
	}
}

// The keychain item name is per-profile so two workspaces' tokens coexist, and
// the legacy name stays unsuffixed so migration need not touch the keychain.
func TestKeychainItemNames(t *testing.T) {
	if got, want := KeychainItemName("staging"), "kontext-install-token.staging"; got != want {
		t.Errorf("KeychainItemName() = %q, want %q", got, want)
	}
	if got, want := LegacyKeychainItemName(), "kontext-install-token"; got != want {
		t.Errorf("LegacyKeychainItemName() = %q, want %q", got, want)
	}
	if KeychainItemName("prod") == KeychainItemName("staging") {
		t.Error("KeychainItemName() collides across profiles")
	}
}

func TestActivePathHelpersPropagateErrNoActive(t *testing.T) {
	withRoot(t)
	if _, err := ActiveManagedConfigPath(); !errors.Is(err, ErrNoActive) {
		t.Errorf("ActiveManagedConfigPath() error = %v, want ErrNoActive", err)
	}
	if _, err := ActiveInstallationPath(); !errors.Is(err, ErrNoActive) {
		t.Errorf("ActiveInstallationPath() error = %v, want ErrNoActive", err)
	}
	if _, err := ActiveDBPath(); !errors.Is(err, ErrNoActive) {
		t.Errorf("ActiveDBPath() error = %v, want ErrNoActive", err)
	}
}

func TestSetActiveReplacesPointerAtomically(t *testing.T) {
	root := withRoot(t)
	for _, name := range []string{"prod", "staging"} {
		if _, err := Create(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := SetActive("prod"); err != nil {
		t.Fatal(err)
	}
	if err := SetActive("staging"); err != nil {
		t.Fatalf("SetActive() switch error = %v", err)
	}
	name, err := ActiveName()
	if err != nil {
		t.Fatal(err)
	}
	if name != "staging" {
		t.Fatalf("ActiveName() = %q, want %q", name, "staging")
	}
	// No temp files left behind to be mistaken for a profile or a pointer.
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".tmp" {
			t.Errorf("SetActive() left a temp file: %s", entry.Name())
		}
	}
}
