// Package profile owns the on-disk layout for named local installations —
// "profiles" — each binding one workspace on one backend to its own config,
// installation identity, install token, and ledger cache.
//
// A profile is the unit that `kontext profile use` switches between. Only one
// is ever active: the `active` pointer file names it, and every profile-scoped
// path resolves through that name. Keeping the pointer as the single mutable
// piece of state is what makes a switch atomic — nothing else on disk moves.
//
// This package is deliberately a leaf: it resolves paths and validates names
// and nothing else. managedconfig and installation both import it, so it must
// import neither.
//
// # Legacy fallback
//
// Installs that predate profiles have no `active` pointer, and their state
// sits directly under Root() rather than under profiles/<name>/. Callers treat
// a missing pointer as "use the legacy paths", so an install that never runs a
// profile command keeps resolving exactly the paths it always has. Migration
// into profile "default" happens once, explicitly, in internal/setup.
package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// EnvRoot overrides the profile root directory. Tests set it; the
	// LaunchAgent never does, so a switch cannot depend on an environment
	// variable the daemon does not inherit.
	EnvRoot = "KONTEXT_PROFILE_ROOT"

	// DefaultName is the profile a pre-profile install migrates into.
	DefaultName = "default"

	activeFileName  = "active"
	profilesDirName = "profiles"
)

var (
	// ErrNoActive means no profile pointer exists: either this install
	// predates profiles, or nothing has been set up yet. Callers fall back to
	// the legacy (unprofiled) paths.
	ErrNoActive = errors.New("no active profile")

	ErrNotFound = errors.New("profile not found")
	ErrExists   = errors.New("profile already exists")
)

// namePattern is intentionally strict: a profile name becomes both a path
// segment and a keychain service-name suffix, so anything that could traverse
// a directory or confuse `security` is rejected outright rather than escaped.
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ValidateName reports whether name is usable as a profile name.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("profile name must not be empty")
	}
	if !namePattern.MatchString(name) {
		return fmt.Errorf("invalid profile name %q: use 1-32 characters of a-z, 0-9, '-' or '_', starting with a letter or digit", name)
	}
	return nil
}

// Root is the directory holding the active pointer and the profiles/ tree, or
// "" when the home directory cannot be resolved.
func Root() string {
	if root := strings.TrimSpace(os.Getenv(EnvRoot)); root != "" {
		return root
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, "Library", "Application Support", "Kontext")
}

// ActivePath is the active-pointer file location, or "" without a root.
func ActivePath() string {
	root := Root()
	if root == "" {
		return ""
	}
	return filepath.Join(root, activeFileName)
}

// ProfilesDir is the parent of every profile directory, or "" without a root.
func ProfilesDir() string {
	root := Root()
	if root == "" {
		return ""
	}
	return filepath.Join(root, profilesDirName)
}

// Dir is the directory owning name's state. It does not check existence.
func Dir(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	parent := ProfilesDir()
	if parent == "" {
		return "", errors.New("cannot resolve your home directory")
	}
	return filepath.Join(parent, name), nil
}

// ActiveName reads the active pointer, returning ErrNoActive when it is
// absent. A pointer naming something unusable is an error, never a silent
// fallback to the legacy paths: that would quietly stream a profile's events
// to whatever the unprofiled config happens to say.
func ActiveName() (string, error) {
	path := ActivePath()
	if path == "" {
		return "", errors.New("cannot resolve your home directory")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNoActive
		}
		return "", err
	}
	name := strings.TrimSpace(string(data))
	if name == "" {
		return "", fmt.Errorf("active profile pointer %s is empty", path)
	}
	if err := ValidateName(name); err != nil {
		return "", fmt.Errorf("active profile pointer %s: %w", path, err)
	}
	return name, nil
}

// ActiveDir is the active profile's directory, or ErrNoActive.
func ActiveDir() (string, error) {
	name, err := ActiveName()
	if err != nil {
		return "", err
	}
	return Dir(name)
}

// Exists reports whether name has a directory on disk.
func Exists(name string) (bool, error) {
	dir, err := Dir(name)
	if err != nil {
		return false, err
	}
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return info.IsDir(), nil
}

// List returns the existing profile names in lexical order. A missing
// profiles/ directory is not an error — it is an install that predates
// profiles, which has none.
func List() ([]string, error) {
	parent := ProfilesDir()
	if parent == "" {
		return nil, errors.New("cannot resolve your home directory")
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		// Skip rather than fail: a stray directory should not make `profile
		// ls` unusable, and it can never be selected because every read path
		// validates the name too.
		if ValidateName(entry.Name()) != nil {
			continue
		}
		names = append(names, entry.Name())
	}
	return names, nil
}

// Create makes name's directory, returning ErrExists if it already has one.
func Create(name string) (string, error) {
	dir, err := Dir(name)
	if err != nil {
		return "", err
	}
	exists, err := Exists(name)
	if err != nil {
		return "", err
	}
	if exists {
		return "", fmt.Errorf("%w: %s", ErrExists, name)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return dir, nil
}

// SetActive points the active pointer at name, which must already exist. The
// write is a temp-file rename so a concurrent reader sees either the old name
// or the new one, never a truncated file.
func SetActive(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	exists, err := Exists(name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	path := ActivePath()
	if path == "" {
		return errors.New("cannot resolve your home directory")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	temp, err := os.CreateTemp(filepath.Dir(path), ".active-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)

	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.WriteString(name + "\n"); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// ClearActive removes the pointer, returning the install to legacy-path
// resolution. Uninstall uses it; switching never does.
func ClearActive() error {
	path := ActivePath()
	if path == "" {
		return errors.New("cannot resolve your home directory")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Remove deletes name's directory and everything under it. It refuses to
// remove the active profile: callers must switch away first, so a machine is
// never left with a pointer aimed at nothing.
func Remove(name string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	exists, err := Exists(name)
	if err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	active, err := ActiveName()
	if err != nil && !errors.Is(err, ErrNoActive) {
		return err
	}
	if active == name {
		return fmt.Errorf("profile %q is active; switch to another profile before removing it", name)
	}
	dir, err := Dir(name)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func syncDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
