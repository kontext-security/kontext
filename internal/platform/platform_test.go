package platform_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/installation"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/mcpconfig"
	"github.com/kontext-security/kontext/internal/platform"
	"github.com/kontext-security/kontext/internal/profile"
)

func join(t *testing.T, dir func() (string, error), elem ...string) string {
	t.Helper()
	base, err := dir()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(append([]string{base}, elem...)...)
}

// The values on macOS and Linux, spelled out: the tests below compare with
// constants that will derive from this package once their call sites move.
func TestDirectoriesOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("platform_windows_test.go covers Windows")
	}
	claude := "/Library/Application Support/ClaudeCode"
	if runtime.GOOS == "linux" {
		claude = "/etc/claude-code"
	}
	for _, test := range []struct{ got, want string }{
		{join(t, platform.SystemConfigDir), "/Library/Application Support/Kontext"},
		{platform.ClaudeManagedDir(), claude},
		{join(t, platform.CodexSystemDir), "/etc/codex"},
	} {
		if test.got != test.want {
			t.Errorf("directory = %q, want %q", test.got, test.want)
		}
	}
}

// The directories give the paths the packages not yet moved use today. On
// Windows those literals are still the macOS ones.
func TestDirectoriesMatchTodaysPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		return
	}
	for _, test := range []struct{ got, want string }{
		{join(t, platform.SystemConfigDir, "managed.json"), managedconfig.DefaultPath},
		{join(t, platform.SystemConfigDir, "install-token"), managedconfig.InstallTokenFilePath},
		{join(t, platform.SystemConfigDir, "deployment-version"), managedconfig.DeploymentVersionPath},
		{join(t, platform.SystemConfigDir, "installation.json"), installation.DefaultPath},
		{join(t, platform.CodexSystemDir, "hooks.json"), codexmanaged.SystemHooksPath},
		{join(t, platform.CodexSystemDir, "config.toml"), hookinstall.SystemConfigPath},
	} {
		if test.got != test.want {
			t.Errorf("path = %q, want %q", test.got, test.want)
		}
	}
}

// Claude Code reads its managed MCP file beside its managed settings, so what
// Kontext looks up on each OS is the file Claude Code would use there.
func TestManagedMCPFileIsWhereClaudeCodeReadsIt(t *testing.T) {
	want := map[string]string{
		"darwin":  "/Library/Application Support/ClaudeCode/managed-mcp.json",
		"linux":   "/etc/claude-code/managed-mcp.json",
		"windows": `C:\Program Files\ClaudeCode\managed-mcp.json`,
	}[runtime.GOOS]
	if got := mcpconfig.ManagedMCPPath; got != want {
		t.Fatalf("ManagedMCPPath = %q, want %q", got, want)
	}
}

func TestUserStateDirIsTheProfileRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("profile.Root moves to the user state directory in its own change")
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv(profile.EnvRoot, "")
	if got, want := join(t, platform.UserStateDir), profile.Root(); got != want {
		t.Fatalf("UserStateDir() = %q, want profile.Root() %q", got, want)
	}
}
