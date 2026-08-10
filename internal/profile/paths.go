package profile

import (
	"path/filepath"
	"strings"
)

// A profile directory mirrors the legacy root layout entry for entry —
// managed.json, installation.json, managed-observe/ — so migration is a move
// of three names and the two layouts stay easy to reason about side by side.
const (
	ManagedConfigFile = "managed.json"
	InstallationFile  = "installation.json"
	ManagedObserveDir = "managed-observe"
	ManagedObserveDB  = "guard.db"
	// WorkspaceFile records which workspace a profile is bound to, so listings
	// can say "staging · Acme Corp" instead of making a human recognize a
	// backend hostname. It is a cache of what the hosted API reported at setup
	// time, never an input to any decision.
	WorkspaceFile = "workspace.json"
	// ModelCacheDirName holds cached guardrail-LLM weights. It is machine-scoped
	// and lives at the ROOT rather than inside a profile — see SharedDir. Named
	// here because both the resolver and the migration need to agree on it.
	ModelCacheDirName  = "judge-models"
	keychainItemPrefix = "kontext-install-token"
)

// MigratedEntries are the root-relative names that migration moves out of the
// legacy root and into profiles/<name>/. managed-observe/ carries the ledger
// database with its -wal/-shm siblings, the export cursor, and the policy
// cache, so it moves as a directory rather than file by file.
var MigratedEntries = []string{ManagedConfigFile, InstallationFile, ManagedObserveDir}

// SharedDir returns <root>/<name> when insidePath lies within this root's
// profiles tree, and "" otherwise.
//
// It exists for machine-scoped artifacts that must NOT be duplicated per
// profile. Cached model weights are the motivating case: they are hundreds of
// megabytes, identical for every workspace, and their location is derived from
// the ledger database's directory — which profiles made per-profile. Without
// hoisting, adding a profile would silently re-download them.
//
// Returning "" for anything outside the profiles tree keeps `kontext guard`,
// whose database lives elsewhere, on exactly its existing layout.
func SharedDir(insidePath, name string) string {
	root := Root()
	parent := ProfilesDir()
	if root == "" || parent == "" || insidePath == "" {
		return ""
	}
	rel, err := filepath.Rel(parent, insidePath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	return filepath.Join(root, name)
}

// LegacyPath resolves a root-relative name in the PRE-profile layout, where
// state sat directly under the root rather than under profiles/<name>/.
//
// Both layouts share one root, so the legacy paths are defined in terms of it.
// That keeps EnvRoot coherent: overriding the root moves the profiled and
// unprofiled views together instead of leaving a caller resolving profiles in a
// temp directory and legacy state in the real home. Returns "" without a root.
func LegacyPath(name string) string {
	root := Root()
	if root == "" {
		return ""
	}
	return filepath.Join(root, name)
}

// ManagedConfigPath is where name's managed config lives.
func ManagedConfigPath(name string) (string, error) {
	dir, err := Dir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ManagedConfigFile), nil
}

// InstallationPath is where name's installation identity lives. Each profile
// gets its own: the same device enrolled in two workspaces must not present
// one shared installation id to both.
func InstallationPath(name string) (string, error) {
	dir, err := Dir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, InstallationFile), nil
}

// WorkspacePath is where name's cached workspace label lives.
func WorkspacePath(name string) (string, error) {
	dir, err := Dir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, WorkspaceFile), nil
}

// DBPath is name's ledger cache. Per-profile databases are what keep an export
// backlog captured for one workspace from being flushed to another: the stream
// cursor is derived from the database's directory, so it moves with it.
func DBPath(name string) (string, error) {
	dir, err := Dir(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ManagedObserveDir, ManagedObserveDB), nil
}

// KeychainItemName is the login-keychain generic-password service name holding
// name's install token. The legacy (pre-profile) install owns the unsuffixed
// name, so migration into "default" can keep pointing at the existing item
// without touching the keychain at all.
func KeychainItemName(name string) string {
	if err := ValidateName(name); err != nil {
		return ""
	}
	return keychainItemPrefix + "." + name
}

// LegacyKeychainItemName is the single service name used before profiles.
func LegacyKeychainItemName() string {
	return keychainItemPrefix
}

// ActiveManagedConfigPath resolves the active profile's managed config, or
// ErrNoActive when this install predates profiles.
func ActiveManagedConfigPath() (string, error) {
	name, err := ActiveName()
	if err != nil {
		return "", err
	}
	return ManagedConfigPath(name)
}

// ActiveInstallationPath resolves the active profile's installation identity,
// or ErrNoActive when this install predates profiles.
func ActiveInstallationPath() (string, error) {
	name, err := ActiveName()
	if err != nil {
		return "", err
	}
	return InstallationPath(name)
}

// ActiveDBPath resolves the active profile's ledger cache, or ErrNoActive when
// this install predates profiles.
func ActiveDBPath() (string, error) {
	name, err := ActiveName()
	if err != nil {
		return "", err
	}
	return DBPath(name)
}
