package managedobserve

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

// TestBrewTapTrustE2E runs against the Mac's real Homebrew and Kontext cask, with
// Homebrew's trust store moved to a temporary folder (XDG_CONFIG_HOME), so the
// user's own trust.json is never read or written. Run it on a Mac with Homebrew 7
// and the cask installed:
//
//	KONTEXT_BREW_E2E=1 go test -run TestBrewTapTrustE2E -v ./internal/managedobserve
func TestBrewTapTrustE2E(t *testing.T) {
	if os.Getenv("KONTEXT_BREW_E2E") == "" {
		t.Skip("set KONTEXT_BREW_E2E=1 to run against the real Homebrew")
	}
	resetUpdaterSeams(t)
	executablePath = func() (string, error) { return "/opt/homebrew/bin/kontext", nil }
	// Leave the Mac's taps as they are: skip the refresh, run every other brew
	// call for real, and never let an upgrade through, even if the trust check
	// passes (HOMEBREW_NO_REQUIRE_TAP_TRUST, Homebrew before 7).
	runCommand = func(ctx context.Context, env []string, path string, args ...string) (string, error) {
		switch args[0] {
		case "update-if-needed":
			return "", nil
		case "upgrade":
			t.Fatalf("the test reached brew upgrade: %v", args)
		}
		return runCommandOutput(ctx, env, path, args...)
	}
	install, ok := currentHomebrewInstall()
	if !ok || install.kind != "--cask" {
		t.Fatalf("needs the Kontext cask under /opt/homebrew: %+v %v", install, ok)
	}
	version, _ := exec.Command(install.brewPath, "--version").Output()
	t.Logf("%s", bytes.SplitN(version, []byte("\n"), 2)[0])

	store := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", store)
	trustFile := filepath.Join(store, "homebrew", "trust.json")
	doctor := func() string {
		var out bytes.Buffer
		printAutoUpdate(&out, func(format string, args ...any) { fmt.Fprintf(&out, "WARNING: "+format+"\n", args...) })
		return out.String()
	}

	// Empty trust store, as for a cask installed before Homebrew 7.
	changed, _, err := checkHomebrewUpgrade(context.Background(), install, diagnostic.Logger{})
	t.Logf("untrusted: changed=%v err=%v", changed, err)
	if changed || err == nil || !strings.Contains(err.Error(), "Run: "+install.brewPath+" trust --cask kontext-security/tap/kontext") {
		t.Fatalf("untrusted cask: changed=%v err=%v, want the brew trust command", changed, err)
	}
	if _, statErr := os.Stat(trustFile); !os.IsNotExist(statErr) {
		t.Fatalf("the updater wrote Homebrew's trust store: %v", statErr)
	}
	out := doctor()
	t.Logf("doctor, untrusted:\n%s", out)
	if !strings.Contains(out, "WARNING: Homebrew does not trust kontext-security/tap/kontext") || !strings.Contains(out, "brew trust --cask kontext-security/tap/kontext") {
		t.Fatal("doctor does not show the brew trust command")
	}

	// The user trusts the cask; the check then lets the upgrade run.
	if trusted, err := exec.Command(install.brewPath, "trust", "--cask", homebrewFormula).CombinedOutput(); err != nil {
		t.Fatalf("brew trust: %v\n%s", err, trusted)
	}
	if err := checkTapTrust(context.Background(), install); err != nil {
		t.Fatalf("trusted cask still refused: %v", err)
	}
	out = doctor()
	t.Logf("doctor, trusted:\n%s", out)
	if strings.Contains(out, "brew trust") {
		t.Fatal("doctor asks to trust a trusted cask")
	}
}
