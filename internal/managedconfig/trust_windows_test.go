package managedconfig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSystemPathsAreUnderProgramData(t *testing.T) {
	windowsDir, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	folder := filepath.VolumeName(windowsDir) + `\ProgramData\Kontext\`
	for got, want := range map[string]string{
		DefaultPath:           folder + "managed.json",
		DeploymentVersionPath: folder + "deployment-version",
	} {
		if got != want {
			t.Errorf("path = %q, want %q", got, want)
		}
	}
}

// A standard user can create files under ProgramData, so a file a user could
// have written must not count as the organization's config.
func TestLoadRefusesASystemFileAUserCouldWrite(t *testing.T) {
	t.Setenv(EnvPath, "")
	system := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(system, loopbackConfigJSON(t, "https://example.test", false), 0o600); err != nil {
		t.Fatal(err)
	}
	withSystemPath(t, system)
	readSystemFile = readAdminOnly
	_, err := Load()
	if !errors.Is(err, ErrUntrustedSystemConfig) {
		t.Fatalf("Load() error = %v, want %v", err, ErrUntrustedSystemConfig)
	}
	if !strings.Contains(err.Error(), system) {
		t.Fatalf("error = %v, want it to name %s", err, system)
	}
}

// A real admin-only file passes the check and reaches the parser.
func TestLoadPassesAnAdminOnlyFileToTheParser(t *testing.T) {
	t.Setenv(EnvPath, "")
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	withSystemPath(t, filepath.Join(dir, "kernel32.dll"))
	readSystemFile = readAdminOnly
	_, err = Load()
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("Load() error = %v, want a JSON syntax error", err)
	}
}

func TestReadAdminOnlyKeepsANotFoundError(t *testing.T) {
	if _, err := readAdminOnly(filepath.Join(os.Getenv("SystemRoot"), "kontext-absent.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, want not-exist", err)
	}
}
