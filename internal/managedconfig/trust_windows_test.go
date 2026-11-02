package managedconfig

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/fsperm"
	"github.com/kontext-security/kontext/internal/hermetic"
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

// The real check: what this user creates is theirs, so it doesn't count as the
// organization's and doesn't take the machine from anyone. An elevated token's
// files may belong to Administrators, which this can't show.
func TestResolvePathIgnoresAFileThisUserOwns(t *testing.T) {
	t.Setenv(EnvPath, "")
	dir := t.TempDir()
	system := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(system, loopbackConfigJSON(t, "https://example.test", false), 0o600); err != nil {
		t.Fatal(err)
	}
	if found, err := fsperm.FindNotAdminFile(system); err != nil || found == nil {
		t.Skipf("this token's files aren't ruled out: %v, %v", found, err)
	}
	withSystemPath(t, system)
	notAdminFile = systemFileNotAdmins
	home := filepath.Join(dir, "home")
	hermetic.SetHome(t, home)
	if path, scope := ResolvePath(); scope != ScopeUser || path == system {
		t.Fatalf("ResolvePath() = %q, %q; want the user path", path, scope)
	}
	if got := IgnoredSystemFile(); !strings.Contains(got, "is owned by") {
		t.Fatalf("IgnoredSystemFile() = %q, want it to name the owner", got)
	}
	if _, err := Load(); !errors.Is(err, ErrNotManaged) {
		t.Fatalf("Load() error = %v, want %v", err, ErrNotManaged)
	}
}

// A user could keep every other user out of a file they plant, so one this user
// can't open must not take the machine from them either.
func TestResolvePathIgnoresAFileThisUserCantOpen(t *testing.T) {
	t.Setenv(EnvPath, "")
	dir := t.TempDir()
	system := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(system, loopbackConfigJSON(t, "https://example.test", false), 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;0x80;;;OW)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(system, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if file, err := os.Open(system); err == nil {
		file.Close()
		t.Skip("the access list doesn't keep this token out")
	}
	withSystemPath(t, system)
	notAdminFile = systemFileNotAdmins
	hermetic.SetHome(t, filepath.Join(dir, "home"))
	if path, scope := ResolvePath(); scope != ScopeUser || path == system {
		t.Fatalf("ResolvePath() = %q, %q; want the user path", path, scope)
	}
	if got := IgnoredSystemFile(); !strings.Contains(got, "can't be opened by this user") {
		t.Fatalf("IgnoredSystemFile() = %q, want it to say why", got)
	}
}

// With the check on who owns it out of the way, the read still refuses a file that
// isn't admin-only.
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
	readSystemFile, notAdminFile = readAdminOnly, systemFileNotAdmins
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
