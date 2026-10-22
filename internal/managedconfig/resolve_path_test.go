package managedconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

// withSystemPath points the ResolvePath system-path probe at a temp location
// so tests can simulate the presence/absence of an MDM install.
func withSystemPath(t *testing.T, path string) {
	t.Helper()
	previous := systemPath
	systemPath = path
	t.Cleanup(func() { systemPath = previous })
}

func TestResolvePathEnvOverrideWins(t *testing.T) {
	dir := t.TempDir()
	withSystemPath(t, filepath.Join(dir, "system", "managed.json"))
	t.Setenv(EnvPath, "/custom/managed.json")

	path, scope := ResolvePath()
	if path != "/custom/managed.json" || scope != ScopeEnv {
		t.Fatalf("ResolvePath() = %q, %q; want env override", path, scope)
	}
}

func TestResolvePathSystemWinsWhenPresent(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(system, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	withSystemPath(t, system)
	t.Setenv(EnvPath, "")
	hermetic.SetHome(t, filepath.Join(dir, "home"))

	path, scope := ResolvePath()
	if path != system || scope != ScopeSystem {
		t.Fatalf("ResolvePath() = %q, %q; want system path", path, scope)
	}
}

func TestResolvePathFallsBackToUserWhenSystemAbsent(t *testing.T) {
	dir := t.TempDir()
	withSystemPath(t, filepath.Join(dir, "missing", "managed.json"))
	t.Setenv(EnvPath, "")
	home := filepath.Join(dir, "home")
	hermetic.SetHome(t, home)

	path, scope := ResolvePath()
	want := filepath.Join(home, "Library", "Application Support", "Kontext", "managed.json")
	if path != want || scope != ScopeUser {
		t.Fatalf("ResolvePath() = %q, %q; want user path %q", path, scope, want)
	}
}

func TestResolvePathSystemStatErrorDoesNotFallThrough(t *testing.T) {
	// An MDM config whose existence cannot be determined must keep the system
	// scope so the error surfaces on read instead of silently using the user
	// config (a self-serve config must never shadow a managed install).
	dir := t.TempDir()
	blocked := filepath.Join(dir, "blocked")
	if err := os.MkdirAll(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	system := filepath.Join(blocked, "managed.json")
	withSystemPath(t, system)
	t.Setenv(EnvPath, "")
	hermetic.SetHome(t, filepath.Join(dir, "home"))

	if _, err := os.Lstat(system); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Skip("environment does not produce permission errors (running as root?)")
	}

	path, scope := ResolvePath()
	if path != system || scope != ScopeSystem {
		t.Fatalf("ResolvePath() = %q, %q; want system path despite stat error", path, scope)
	}
}

func TestLoadResolvesUserScopeConfig(t *testing.T) {
	dir := t.TempDir()
	withSystemPath(t, filepath.Join(dir, "missing", "managed.json"))
	t.Setenv(EnvPath, "")
	home := filepath.Join(dir, "home")
	hermetic.SetHome(t, home)

	userDir := filepath.Join(home, "Library", "Application Support", "Kontext")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "managed.json"), []byte(validConfigJSON()), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.Scope != ScopeUser {
		t.Fatalf("Load() scope = %q, want %q", loaded.Scope, ScopeUser)
	}
}

func TestLoadInvalidSystemConfigDoesNotFallThroughToUser(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(system, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	withSystemPath(t, system)
	t.Setenv(EnvPath, "")
	home := filepath.Join(dir, "home")
	hermetic.SetHome(t, home)

	userDir := filepath.Join(home, "Library", "Application Support", "Kontext")
	if err := os.MkdirAll(userDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "managed.json"), []byte(validConfigJSON()), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(); err == nil || strings.Contains(err.Error(), "org_123") {
		t.Fatalf("Load() = %v; want parse error from the system config, not user fallback", err)
	}
}

func TestUserPathUsesHomeLibrary(t *testing.T) {
	hermetic.SetHome(t, "/Users/example")
	want := filepath.Join("/Users/example", "Library", "Application Support", "Kontext", "managed.json")
	if got := UserPath(); got != want {
		t.Fatalf("UserPath() = %q, want %q", got, want)
	}
}
