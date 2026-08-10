package setup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

func TestRenameProfileMovesInactiveProfile(t *testing.T) {
	h := switchHarness(t) // prod active, staging inactive
	var out bytes.Buffer

	if err := RenameProfile(context.Background(), "staging", "stg", &out); err != nil {
		t.Fatalf("RenameProfile() error = %v", err)
	}

	if exists, _ := profile.Exists("staging"); exists {
		t.Error("old profile directory still exists")
	}
	exists, err := profile.Exists("stg")
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("new profile directory was not created")
	}
	// State came with it.
	newConfig := filepath.Join(kontextRoot(h.home), "profiles", "stg", "managed.json")
	if _, err := managedconfig.LoadFile(newConfig); err != nil {
		t.Errorf("config did not move: %v", err)
	}
	// The active profile is untouched.
	if active, _ := profile.ActiveName(); active != "prod" {
		t.Errorf("ActiveName() = %q, want prod", active)
	}
}

// Renaming an inactive profile touches nothing the daemon is reading, so there is
// no reason to interrupt observability for a directory move.
func TestRenameInactiveProfileDoesNotRestartTheAgent(t *testing.T) {
	h := switchHarness(t)
	callsBefore := len(h.calls)
	var out bytes.Buffer

	if err := RenameProfile(context.Background(), "staging", "stg", &out); err != nil {
		t.Fatal(err)
	}
	for _, call := range h.calls[callsBefore:] {
		if call.name == "launchctl" {
			t.Errorf("renaming an inactive profile touched launchd: %v", call.args)
		}
	}
}

// Renaming the ACTIVE profile changes the paths the daemon resolves, so it must
// stop, move, re-point, and start — in that order.
func TestRenameActiveProfileRepointsAndRestarts(t *testing.T) {
	h := switchHarness(t)
	callsBefore := len(h.calls)
	var out bytes.Buffer

	if err := RenameProfile(context.Background(), "prod", "production", &out); err != nil {
		t.Fatalf("RenameProfile() error = %v", err)
	}

	active, err := profile.ActiveName()
	if err != nil {
		t.Fatal(err)
	}
	if active != "production" {
		t.Fatalf("ActiveName() = %q, want production", active)
	}

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
}

// The token is found through the ref in the config, not the directory name, so a
// rename needs no keychain access — and therefore triggers no prompt.
func TestRenameProfileNeverTouchesTheKeychain(t *testing.T) {
	h := switchHarness(t)
	callsBefore := len(h.calls)
	var out bytes.Buffer

	if err := RenameProfile(context.Background(), "staging", "stg", &out); err != nil {
		t.Fatal(err)
	}
	for _, call := range h.calls[callsBefore:] {
		if call.name == "security" {
			t.Errorf("rename touched the keychain: %v", call.args)
		}
	}
	// And the renamed profile still resolves its token.
	if err := verifyProfileUsable(context.Background(), "stg"); err != nil {
		t.Errorf("renamed profile is not usable: %v", err)
	}
}

func TestRenameProfileRejectsUnknownAndCollidingNames(t *testing.T) {
	switchHarness(t)
	var out bytes.Buffer

	if err := RenameProfile(context.Background(), "ghost", "whatever", &out); !errors.Is(err, profile.ErrNotFound) {
		t.Errorf("rename of a missing profile = %v, want ErrNotFound", err)
	}
	if err := RenameProfile(context.Background(), "staging", "prod", &out); !errors.Is(err, profile.ErrExists) {
		t.Errorf("rename onto an existing profile = %v, want ErrExists", err)
	}
	if err := RenameProfile(context.Background(), "staging", "../escape", &out); err == nil {
		t.Error("rename to a traversal name = nil, want error")
	}
	// The originals survive every refusal.
	for _, name := range []string{"prod", "staging"} {
		if exists, _ := profile.Exists(name); !exists {
			t.Errorf("profile %q disappeared after a refused rename", name)
		}
	}
}

func TestRenameProfileToSameNameIsNoOp(t *testing.T) {
	h := switchHarness(t)
	callsBefore := len(h.calls)
	var out bytes.Buffer

	if err := RenameProfile(context.Background(), "prod", "prod", &out); err != nil {
		t.Fatalf("RenameProfile() error = %v", err)
	}
	if !strings.Contains(out.String(), "already named") {
		t.Errorf("output = %q, want an already-named notice", out.String())
	}
	if len(h.calls) != callsBefore {
		t.Error("a no-op rename ran commands")
	}
}

// This is the migrate-then-rename path, which is the reason rename exists: the
// migrated profile's token ref is the LEGACY unsuffixed item and does not match
// its name, and that must keep working after the rename.
func TestRenameMigratedProfileKeepsItsLegacyTokenRef(t *testing.T) {
	h := profileHarness(t)
	if err := Run(context.Background(), h.options("kt_legacy", pingServer(t, "kt_legacy"))); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyInstall(context.Background(), nil); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := RenameProfile(context.Background(), profile.DefaultName, "staging", &out); err != nil {
		t.Fatalf("RenameProfile() error = %v", err)
	}

	configPath, err := profile.ManagedConfigPath("staging")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := managedconfig.LoadFile(configPath)
	if err != nil {
		t.Fatalf("renamed config unreadable: %v", err)
	}
	if got := loaded.Config.Credentials.InstallTokenRef.Name; got != KeychainItemName {
		t.Errorf("token ref = %q, want the legacy item %q preserved", got, KeychainItemName)
	}
	// And the token still resolves through it.
	if _, ok := h.keychain[KeychainItemName]; !ok {
		t.Error("legacy keychain item disappeared")
	}
}

// A renamed or migrated profile's token lives under a name that does NOT match
// the profile. Removal must read the ref from the config, or that workspace's
// token is left behind in the keychain.
func TestRemoveProfileDeletesTheTokenNamedByItsConfig(t *testing.T) {
	h := profileHarness(t)
	if err := Run(context.Background(), h.options("kt_legacy", pingServer(t, "kt_legacy"))); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateLegacyInstall(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := RenameProfile(context.Background(), profile.DefaultName, "staging", &out); err != nil {
		t.Fatal(err)
	}
	// Switch away so the profile can be removed.
	if _, err := profile.Create("other"); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("other"); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.keychain[KeychainItemName]; !ok {
		t.Fatal("expected the legacy keychain item to exist before removal")
	}

	if err := RemoveProfile(context.Background(), "staging", &out); err != nil {
		t.Fatalf("RemoveProfile() error = %v", err)
	}
	if _, ok := h.keychain[KeychainItemName]; ok {
		t.Error("the token named by the profile's config survived removal")
	}
	if _, err := os.Lstat(filepath.Join(kontextRoot(h.home), "profiles", "staging")); !os.IsNotExist(err) {
		t.Errorf("profile directory survived removal (err = %v)", err)
	}
}
