package managedconfig

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
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
