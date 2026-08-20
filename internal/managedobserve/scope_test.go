package managedobserve

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/installation"
	"github.com/kontext-security/kontext/internal/managedconfig"
)

func TestInstallationPathForScope(t *testing.T) {
	t.Setenv("HOME", "/Users/example")
	t.Setenv(installation.EnvPath, "")

	userPath := filepath.Join("/Users/example", "Library", "Application Support", "Kontext", "installation.json")

	cases := []struct {
		name  string
		scope managedconfig.Scope
		want  string
	}{
		// System and env-resolved configs keep the enterprise default so MDM
		// daemons behave byte-identically to before self-serve existed.
		{"system scope", managedconfig.ScopeSystem, installation.DefaultPath},
		{"env scope", managedconfig.ScopeEnv, installation.DefaultPath},
		{"empty scope (LoadFile callers)", managedconfig.Scope(""), installation.DefaultPath},
		{"user scope", managedconfig.ScopeUser, userPath},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := installationPathForScope(tc.scope); got != tc.want {
				t.Fatalf("installationPathForScope(%q) = %q, want %q", tc.scope, got, tc.want)
			}
		})
	}
}

func TestInstallationPathForScopeUserWithoutHomeFallsBack(t *testing.T) {
	// Pathological: scope resolved as user but the home dir has since become
	// unavailable. The system default is the only sane landing spot.
	t.Setenv("HOME", "")
	t.Setenv(installation.EnvPath, "")

	if got := installationPathForScope(managedconfig.ScopeUser); got != installation.DefaultPath {
		t.Fatalf("installationPathForScope(user, no home) = %q, want system default", got)
	}
}

func TestInstallationPathForScopeEnvOverrideWins(t *testing.T) {
	t.Setenv("HOME", "/Users/example")
	t.Setenv(installation.EnvPath, "/custom/installation.json")

	if got := installationPathForScope(managedconfig.ScopeUser); got != "/custom/installation.json" {
		t.Fatalf("installationPathForScope(user) = %q, want env override", got)
	}
}

func TestRunDaemonParksOnScopeMismatch(t *testing.T) {
	// A self-serve agent (expected scope "user") must park — not serve, not
	// crash-loop — when config resolution lands on another scope (an MDM
	// config appeared after setup).
	dir := t.TempDir()
	config := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(config, []byte(`{
  "version": "managed-install-v1",
  "cloud_url": "https://api.kontext.dev",
  "mode": "observe",
  "agent": "claude",
  "credentials": {"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managedconfig.EnvPath, config) // resolves as scope "env"
	t.Setenv(EnvExpectedConfigScope, "user")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := RunDaemon(ctx, DaemonOptions{}); err != nil {
		t.Fatalf("RunDaemon() = %v, want clean park until ctx done", err)
	}
	// Parked means it waited for the context, not returned immediately.
	if time.Since(start) < 250*time.Millisecond {
		t.Fatal("RunDaemon returned before context cancellation — did not park")
	}
}

func TestDeploymentVersionWithFallback(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "deployment-version")

	t.Setenv(managedconfig.EnvDeploymentVersionPath, marker)

	// No marker (brew install): the CLI's own version is reported.
	if got := deploymentVersionWithFallback("cli-1.2.3")(); got != "cli-1.2.3" {
		t.Fatalf("fallback = %q, want cli-1.2.3", got)
	}

	// Marker present (MDM package): it wins, evaluated per call.
	if err := os.WriteFile(marker, []byte("0.3.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := deploymentVersionWithFallback("cli-1.2.3")(); got != "0.3.2" {
		t.Fatalf("marker = %q, want 0.3.2", got)
	}
}
