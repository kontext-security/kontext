package setup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/managedobserve"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

// switchHarness sets up two fully-installed profiles and stubs the daemon wait,
// so tests exercise the switch itself rather than launchd timing.
func switchHarness(t *testing.T) *harness {
	t.Helper()
	h := profileHarness(t)
	overrideVar(t, &waitForDaemonRestart, func(_ context.Context, _, _, _ string) (*managedobserve.DaemonStatus, error) {
		return &managedobserve.DaemonStatus{Version: "0.0.0-test", PID: 4242}, nil
	})
	for _, name := range []string{"prod", "staging"} {
		server := pingServer(t, "kt_"+name)
		opts := h.options("kt_"+name, server)
		opts.Profile = name
		if err := Run(context.Background(), opts); err != nil {
			t.Fatalf("Run(%s) error = %v", name, err)
		}
	}
	if err := profile.SetActive("prod"); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestActivateSwitchesPointerAndRestartsAgent(t *testing.T) {
	h := switchHarness(t)
	callsBefore := len(h.calls)
	var out, errOut bytes.Buffer

	if err := Activate(context.Background(), "staging", &out, &errOut); err != nil {
		t.Fatalf("Activate() error = %v (stderr: %s)", err, errOut.String())
	}

	name, err := profile.ActiveName()
	if err != nil {
		t.Fatal(err)
	}
	if name != "staging" {
		t.Fatalf("ActiveName() = %q, want %q", name, "staging")
	}

	// The daemon must be stopped before the pointer moves and started after:
	// it holds the ledger database the switch re-points.
	var order []string
	for _, call := range h.calls[callsBefore:] {
		if call.name == "launchctl" && len(call.args) > 0 {
			if call.args[0] == "bootout" || call.args[0] == "bootstrap" {
				order = append(order, call.args[0])
			}
		}
	}
	if len(order) < 2 || order[0] != "bootout" || order[len(order)-1] != "bootstrap" {
		t.Fatalf("launchctl order = %v, want bootout before bootstrap", order)
	}
	if !strings.Contains(out.String(), "Active profile: staging") {
		t.Errorf("output did not report the new profile:\n%s", out.String())
	}
}
func TestActivateRejectsUnknownProfile(t *testing.T) {
	switchHarness(t)
	var out, errOut bytes.Buffer
	err := Activate(context.Background(), "ghost", &out, &errOut)
	if !errors.Is(err, profile.ErrNotFound) {
		t.Fatalf("Activate() error = %v, want ErrNotFound", err)
	}
	// The previous profile must still be active.
	if name, _ := profile.ActiveName(); name != "prod" {
		t.Fatalf("ActiveName() = %q, want prod to remain active", name)
	}
}

// Switching to a profile whose config is missing would trade a working install
// for a broken one, so it must be refused before the pointer moves.
func TestActivateRefusesProfileWithoutConfig(t *testing.T) {
	h := switchHarness(t)
	if _, err := profile.Create("empty"); err != nil {
		t.Fatal(err)
	}
	callsBefore := len(h.calls)
	var out, errOut bytes.Buffer

	err := Activate(context.Background(), "empty", &out, &errOut)
	if err == nil {
		t.Fatal("Activate() = nil error, want refusal")
	}
	if !strings.Contains(err.Error(), "no config yet") {
		t.Fatalf("error = %v, want a missing-config refusal", err)
	}
	if name, _ := profile.ActiveName(); name != "prod" {
		t.Fatalf("ActiveName() = %q, want prod to remain active", name)
	}
	for _, call := range h.calls[callsBefore:] {
		if call.name == "launchctl" {
			t.Errorf("Activate() touched launchd before validating: %v", call.args)
		}
	}
}

// An unreadable token is the classic silent killer: the daemon starts, cannot
// authenticate, and dies under launchd. Catch it before switching.
func TestActivateRefusesProfileWithUnreadableToken(t *testing.T) {
	h := switchHarness(t)
	delete(h.keychain, "kontext-install-token.staging")
	callsBefore := len(h.calls)
	var out, errOut bytes.Buffer

	err := Activate(context.Background(), "staging", &out, &errOut)
	if err == nil {
		t.Fatal("Activate() = nil error, want refusal")
	}
	if !strings.Contains(err.Error(), "not readable") {
		t.Fatalf("error = %v, want an unreadable-token refusal", err)
	}
	if name, _ := profile.ActiveName(); name != "prod" {
		t.Fatalf("ActiveName() = %q, want prod to remain active", name)
	}
	for _, call := range h.calls[callsBefore:] {
		if call.name == "launchctl" {
			t.Errorf("Activate() touched launchd before validating: %v", call.args)
		}
	}
}

// After a switch the daemon must resolve the NEW profile's database — this is
// the export fence in its end-to-end form.
func TestActivateRepointsResolvedPaths(t *testing.T) {
	h := switchHarness(t)
	var out, errOut bytes.Buffer

	before := managedobserve.DefaultDBPath()
	if err := Activate(context.Background(), "staging", &out, &errOut); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	after := managedobserve.DefaultDBPath()

	if before == after {
		t.Fatalf("DefaultDBPath() unchanged across a switch: %q", before)
	}
	wantSuffix := filepath.Join("profiles", "staging", "managed-observe", "guard.db")
	if !strings.HasSuffix(after, wantSuffix) {
		t.Fatalf("DefaultDBPath() = %q, want it to end with %q", after, wantSuffix)
	}
	if _, err := os.Lstat(filepath.Join(kontextRoot(h.home), "profiles", "staging", "managed.json")); err != nil {
		t.Fatalf("staging config missing after switch: %v", err)
	}
}
