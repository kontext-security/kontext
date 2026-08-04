package profile

import (
	"path/filepath"
	"testing"
)

// Cached model weights are machine-scoped and large. Deriving their location
// from the ledger database's directory — which profiles made per-profile — would
// mean every new profile re-downloads them, so anything inside the profiles tree
// resolves to one shared directory at the root.
func TestSharedDirHoistsPathsInsideTheProfilesTree(t *testing.T) {
	root := withRoot(t)
	want := filepath.Join(root, ModelCacheDirName)

	for _, inside := range []string{
		filepath.Join(root, profilesDirName, "default", ManagedObserveDir),
		filepath.Join(root, profilesDirName, "staging", ManagedObserveDir),
		filepath.Join(root, profilesDirName, "localdev", ManagedObserveDir, "nested"),
	} {
		if got := SharedDir(inside, ModelCacheDirName); got != want {
			t.Errorf("SharedDir(%q) = %q, want %q", inside, got, want)
		}
	}
}

// Two profiles must agree on the shared location — that is the whole point.
func TestSharedDirIsIdenticalAcrossProfiles(t *testing.T) {
	root := withRoot(t)
	a := SharedDir(filepath.Join(root, profilesDirName, "prod", ManagedObserveDir), ModelCacheDirName)
	b := SharedDir(filepath.Join(root, profilesDirName, "staging", ManagedObserveDir), ModelCacheDirName)
	if a == "" || a != b {
		t.Fatalf("SharedDir differs across profiles: %q vs %q", a, b)
	}
}

// Anything outside the profiles tree keeps its existing layout, so `kontext
// guard` — whose database lives elsewhere entirely — is untouched.
func TestSharedDirDeclinesPathsOutsideTheProfilesTree(t *testing.T) {
	root := withRoot(t)
	for _, outside := range []string{
		"",
		filepath.Join(root, ManagedObserveDir),
		filepath.Join(t.TempDir(), "kontext"),
		"/Users/someone/.kontext",
		filepath.Dir(root),
	} {
		if got := SharedDir(outside, ModelCacheDirName); got != "" {
			t.Errorf("SharedDir(%q) = %q, want empty", outside, got)
		}
	}
}
