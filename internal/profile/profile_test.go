package profile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// The pointer transition is a compare-and-set, not a check followed by a
// write: a stale expectation writes nothing, so two processes can never both
// conclude they own the same transition.
func TestCompareAndSetActive(t *testing.T) {
	withRoot(t)
	for _, name := range []string{"a", "b"} {
		if _, err := Create(name); err != nil {
			t.Fatal(err)
		}
	}

	// From no pointer.
	if ok, err := CompareAndSetActive("", "a"); err != nil || !ok {
		t.Fatalf(`CompareAndSetActive("", "a") = %v, %v; want a swap`, ok, err)
	}
	// A stale expectation loses, and writes nothing.
	if ok, err := CompareAndSetActive("", "b"); err != nil || ok {
		t.Fatalf(`CompareAndSetActive("", "b") = %v, %v; want no swap`, ok, err)
	}
	if name, err := ActiveName(); err != nil || name != "a" {
		t.Fatalf("ActiveName() = %q, %v; want the losing swap to have written nothing", name, err)
	}
	// A matching expectation moves it.
	if ok, err := CompareAndSetActive("a", "b"); err != nil || !ok {
		t.Fatalf(`CompareAndSetActive("a", "b") = %v, %v; want a swap`, ok, err)
	}
	// And clears it.
	if ok, err := CompareAndSetActive("b", ""); err != nil || !ok {
		t.Fatalf(`CompareAndSetActive("b", "") = %v, %v; want a clear`, ok, err)
	}
	if _, err := ActiveName(); !errors.Is(err, ErrNoActive) {
		t.Fatalf("ActiveName() error = %v, want ErrNoActive after the clear", err)
	}
}

// A live claim pins the directory: rm and rename refuse while the claiming
// process runs, and stop refusing the moment its claim is released.
func TestRemoveAndRenameRefuseALiveClaim(t *testing.T) {
	withRoot(t)
	release, err := Claim("mid-setup")
	if err != nil {
		t.Fatal(err)
	}
	if err := Remove("mid-setup"); err == nil || !strings.Contains(err.Error(), "still being created") {
		t.Fatalf("Remove() = %v, want a live-claim refusal", err)
	}
	if _, err := Rename("mid-setup", "elsewhere"); err == nil || !strings.Contains(err.Error(), "still being created") {
		t.Fatalf("Rename() = %v, want a live-claim refusal", err)
	}
	release(false)
	if err := Remove("mid-setup"); err != nil {
		t.Fatalf("Remove() after release = %v", err)
	}
}

// A crashed run's claim must not pin its directory forever: a marker whose
// pid is dead stops counting immediately — no grace period, no manual repair.
func TestStaleClaimDoesNotBlockRemoval(t *testing.T) {
	withRoot(t)
	if _, err := Create("crashed"); err != nil {
		t.Fatal(err)
	}
	dir, err := Dir("crashed")
	if err != nil {
		t.Fatal(err)
	}
	// Far above any real pid_max, so it can never name a running process.
	if err := os.WriteFile(filepath.Join(dir, ".claim-99999999-x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Remove("crashed"); err != nil {
		t.Fatalf("Remove() with a dead process's claim = %v, want success", err)
	}
}

// Renaming the active profile moves the pointer in the same locked step, and
// an inactive profile's rename leaves the pointer alone.
func TestRenameRepointsTheActivePointerAtomically(t *testing.T) {
	withRoot(t)
	for _, name := range []string{"a", "c"} {
		if _, err := Create(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := SetActive("a"); err != nil {
		t.Fatal(err)
	}

	repointed, err := Rename("a", "b")
	if err != nil || !repointed {
		t.Fatalf("Rename(a, b) = %v, %v; want the active rename to repoint", repointed, err)
	}
	if name, err := ActiveName(); err != nil || name != "b" {
		t.Fatalf("ActiveName() = %q, %v; want the pointer moved to \"b\"", name, err)
	}

	repointed, err = Rename("c", "d")
	if err != nil || repointed {
		t.Fatalf("Rename(c, d) = %v, %v; want an inactive rename to leave the pointer", repointed, err)
	}
	if name, _ := ActiveName(); name != "b" {
		t.Fatalf("ActiveName() = %q, want it untouched by an inactive rename", name)
	}
}
