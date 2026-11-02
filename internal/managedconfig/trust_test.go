package managedconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

// The system file goes through the trust check and a user file does not, on
// every OS, so the wiring can't come undone on the OSes that have no check yet.
func TestLoadChecksOnlyTheSystemFile(t *testing.T) {
	t.Setenv(EnvPath, "")
	refused := errors.New("refused by the check")
	var checked []string
	check := func(path string) ([]byte, error) {
		checked = append(checked, path)
		return nil, refused
	}

	system := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(system, loopbackConfigJSON(t, "https://example.test", false), 0o600); err != nil {
		t.Fatal(err)
	}
	withSystemPath(t, system)
	readSystemFile = check
	if _, err := Load(); !errors.Is(err, refused) {
		t.Fatalf("system scope: Load() error = %v, want the check's refusal", err)
	}
	if len(checked) != 1 || checked[0] != system {
		t.Fatalf("checked %q, want only %q", checked, system)
	}

	checked = nil
	t.Setenv(EnvPath, system)
	if _, err := Load(); err != nil {
		t.Fatalf("env scope: Load() error = %v", err)
	}
	if len(checked) != 0 {
		t.Fatalf("env scope checked %q, want nothing", checked)
	}
}

type foundNotAdmin string

func (f foundNotAdmin) String() string { return string(f) }

// A system file that can't be an administrator's isn't the organization's, so it
// must not take the machine from its users: their own config applies, and doctor
// can say why.
func TestLoadIgnoresASystemFileThatIsNotAnAdmins(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(system, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	withSystemPath(t, system)
	t.Setenv(EnvPath, "")
	home := filepath.Join(dir, "home")
	hermetic.SetHome(t, home)
	const reason = "owned by someone"
	notAdminFile = func(string) (fmt.Stringer, error) { return foundNotAdmin(reason), nil }
	readSystemFile = func(string) ([]byte, error) {
		t.Error("read a file that doesn't count")
		return nil, nil
	}

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
	if got := IgnoredSystemFile(); got != reason {
		t.Fatalf("IgnoredSystemFile() = %q, want %q", got, reason)
	}
	// With an override the system path isn't looked at, so nothing is being ignored.
	t.Setenv(EnvPath, filepath.Join(userDir, "managed.json"))
	if got := IgnoredSystemFile(); got != "" {
		t.Fatalf("with an override, IgnoredSystemFile() = %q, want empty", got)
	}
}

// What can't be determined doesn't ignore the file: the system scope stays, so a
// self-serve config can't shadow a managed install, and the read reports it.
func TestResolvePathKeepsTheSystemFileWhenItCantTell(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(system, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	withSystemPath(t, system)
	t.Setenv(EnvPath, "")
	hermetic.SetHome(t, filepath.Join(dir, "home"))
	notAdminFile = func(string) (fmt.Stringer, error) { return nil, errors.New("can't tell") }

	if path, scope := ResolvePath(); path != system || scope != ScopeSystem {
		t.Fatalf("ResolvePath() = %q, %q; want the system path", path, scope)
	}
	if got := IgnoredSystemFile(); got != "" {
		t.Fatalf("IgnoredSystemFile() = %q, want empty", got)
	}
}

// Without a system folder the scope can't be decided, so user config must not
// stand in for it.
func TestLoadFailsWithoutASystemFolder(t *testing.T) {
	t.Setenv(EnvPath, "")
	broken := errors.New("no system folder")
	errSystemDir = broken
	t.Cleanup(func() { errSystemDir = nil })
	if _, err := Load(); !errors.Is(err, broken) {
		t.Fatalf("Load() error = %v, want %v", err, broken)
	}
}

// The deployment marker goes through the check as well; refused reads as absent.
func TestDeploymentVersionChecksTheDefaultFile(t *testing.T) {
	t.Setenv(EnvDeploymentVersionPath, "")
	path := filepath.Join(t.TempDir(), "deployment-version")
	if err := os.WriteFile(path, []byte("1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	previousPath, previousRead := DeploymentVersionPath, readSystemFile
	t.Cleanup(func() { DeploymentVersionPath, readSystemFile = previousPath, previousRead })
	DeploymentVersionPath = path

	readSystemFile = os.ReadFile
	if got := DeploymentVersion(); got != "1.2.3" {
		t.Fatalf("DeploymentVersion() = %q, want 1.2.3", got)
	}
	readSystemFile = func(string) ([]byte, error) { return nil, errors.New("refused") }
	if got := DeploymentVersion(); got != "" {
		t.Fatalf("refused: DeploymentVersion() = %q, want empty", got)
	}
}
