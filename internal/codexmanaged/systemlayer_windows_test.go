package codexmanaged

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext/internal/fsperm"
	"golang.org/x/sys/windows"
)

// A standard user can create Codex's system folder under ProgramData, so a file
// there that a user could have written must not count as installed. The same
// file does count with a plain read, so the refusal is what keeps it out.
func TestInspectInstallationRefusesASystemFileAUserCouldWrite(t *testing.T) {
	valid, err := TemplateJSON(`C:\Program Files\Kontext\kontext`)
	if err != nil {
		t.Fatal(err)
	}
	system := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(system, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	withSystemHooks(t, system, os.ReadFile)
	if got, _ := InspectInstallation(InstallationPaths{SystemHooks: system}); len(got.Layers) != 1 {
		t.Fatalf("with a plain read, layers = %+v, want one", got.Layers)
	}
	readSystemHooks = readAdminOnly
	got, err := InspectInstallation(InstallationPaths{SystemHooks: system})
	var refused *fsperm.NotAdminOnlyError
	if !errors.As(err, &refused) {
		t.Fatalf("InspectInstallation() error = %v, want a refusal", err)
	}
	if len(got.Layers) != 0 {
		t.Fatalf("layers = %+v, want none", got.Layers)
	}
}

// A real admin-only file passes the check and reaches the parser.
func TestInspectInstallationPassesAnAdminOnlyFileToTheParser(t *testing.T) {
	dir, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	system := filepath.Join(dir, "kernel32.dll")
	withSystemHooks(t, system, readAdminOnly)
	_, err = InspectInstallation(InstallationPaths{SystemHooks: system})
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("InspectInstallation() error = %v, want a JSON syntax error", err)
	}
}
