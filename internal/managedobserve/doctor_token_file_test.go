package managedobserve

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/managedconfig"
)

// An organization-managed install keeps the token in the launcher's file, not
// in the shell doctor runs from; doctor must judge that file.
func TestPrintStatusOrgManagedTokenComesFromLauncherFile(t *testing.T) {
	newOpts := func(t *testing.T) (doctorOptions, string) {
		t.Helper()
		env := newDoctorTestEnv(t)
		t.Setenv("KONTEXT_INSTALL_TOKEN", "")
		opts := env.options()
		opts.LoadConfig = env.loadConfig(managedconfig.ScopeSystem)
		opts.LaunchAgentPresent = func() bool { return false }
		opts.InstallTokenFile = filepath.Join(env.dir, "install-token")
		return opts, opts.InstallTokenFile
	}

	t.Run("missing file names the file, not the keychain", func(t *testing.T) {
		opts, tokenFile := newOpts(t)
		var out bytes.Buffer
		_, report := printStatus(&out, "1.2.3", opts)
		output := out.String()
		if report.InstallTokenReadable {
			t.Fatalf("report.InstallTokenReadable = true, want false; output = %q", output)
		}
		if !strings.Contains(output, "install token file is not readable") || !strings.Contains(output, tokenFile) {
			t.Fatalf("output = %q, want a warning naming %s", output, tokenFile)
		}
		if strings.Contains(output, "keychain") {
			t.Fatalf("output = %q, want no keychain advice on an organization-managed install", output)
		}
	})

	t.Run("readable file counts as readable token", func(t *testing.T) {
		opts, tokenFile := newOpts(t)
		if err := os.WriteFile(tokenFile, []byte("0123456789abcdef0123456789abcdef\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		_, report := printStatus(&out, "1.2.3", opts)
		output := out.String()
		if !report.InstallTokenReadable {
			t.Fatalf("report.InstallTokenReadable = false, want true; output = %q", output)
		}
		if !strings.Contains(output, "install token: readable ("+tokenFile) {
			t.Fatalf("output = %q, want the token file reported as readable", output)
		}
		if strings.Contains(output, "install token is not readable") || strings.Contains(output, "install token file is not readable") {
			t.Fatalf("output = %q, want no token warning", output)
		}
	})
}
