package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/profile"
)

func TestLoadInventoryOnEmptyMachine(t *testing.T) {
	profileHarness(t)
	inventory, err := LoadInventory()
	if err != nil {
		t.Fatalf("LoadInventory() error = %v", err)
	}
	if inventory.Active != "" {
		t.Errorf("Active = %q, want empty", inventory.Active)
	}
	if inventory.LegacyInstall {
		t.Error("LegacyInstall = true on a machine with nothing installed")
	}
	if len(inventory.Profiles) != 0 {
		t.Errorf("Profiles = %v, want none", inventory.Profiles)
	}
}

// A pre-profile install must be reported as such, so `ls` can point the user at
// `profile migrate` instead of claiming there is nothing here.
func TestLoadInventoryDetectsLegacyInstall(t *testing.T) {
	h := profileHarness(t)
	if err := Run(context.Background(), h.options("kt_legacy", pingServer(t, "kt_legacy"))); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	inventory, err := LoadInventory()
	if err != nil {
		t.Fatalf("LoadInventory() error = %v", err)
	}
	if !inventory.LegacyInstall {
		t.Error("LegacyInstall = false, want true for an unprofiled install")
	}
	if inventory.Active != "" {
		t.Errorf("Active = %q, want empty before migration", inventory.Active)
	}
}

func TestLoadInventoryReportsProfileDetail(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_staging")
	opts := h.options("kt_staging", server)
	opts.Profile = "staging"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}

	inventory, err := LoadInventory()
	if err != nil {
		t.Fatalf("LoadInventory() error = %v", err)
	}
	if inventory.Active != "staging" {
		t.Fatalf("Active = %q, want staging", inventory.Active)
	}
	if inventory.LegacyInstall {
		t.Error("LegacyInstall = true after a profile-only setup")
	}
	if len(inventory.Profiles) != 1 {
		t.Fatalf("Profiles = %v, want exactly one", inventory.Profiles)
	}
	got := inventory.Profiles[0]
	if !got.Active {
		t.Error("profile is not marked active")
	}
	if got.CloudURL != server.URL {
		t.Errorf("CloudURL = %q, want %q", got.CloudURL, server.URL)
	}
	if got.InstallTokenRef != "keychain:kontext-install-token.staging" {
		t.Errorf("InstallTokenRef = %q", got.InstallTokenRef)
	}
	if got.InstallationID == "" {
		t.Error("InstallationID is empty")
	}
	if got.Error != "" {
		t.Errorf("Error = %q, want empty", got.Error)
	}
	// The ping response's organization name is cached so a listing can name the
	// workspace rather than a hostname.
	if got.OrganizationID == "" {
		t.Error("OrganizationID is empty; the ping response was not cached")
	}
	if !strings.Contains(got.Workspace, got.OrganizationID) {
		t.Errorf("Workspace = %q, want it to include organization id %q", got.Workspace, got.OrganizationID)
	}
}

// A profile directory with no config must be reported, not skipped: a silently
// short listing is how a machine looks healthy while a workspace is unusable.
func TestLoadInventoryReportsUnusableProfile(t *testing.T) {
	profileHarness(t)
	if _, err := profile.Create("halfway"); err != nil {
		t.Fatal(err)
	}
	inventory, err := LoadInventory()
	if err != nil {
		t.Fatalf("LoadInventory() error = %v", err)
	}
	if len(inventory.Profiles) != 1 {
		t.Fatalf("Profiles = %v, want one", inventory.Profiles)
	}
	if inventory.Profiles[0].Error == "" {
		t.Error("Error is empty for a profile with no config")
	}
}

// LoadInventory is what a polling GUI calls; it must never reach for the
// keychain, or a background poll turns into an authorization prompt loop.
func TestLoadInventoryNeverTouchesTheKeychain(t *testing.T) {
	h := profileHarness(t)
	for _, name := range []string{"prod", "staging"} {
		opts := h.options("kt_"+name, pingServer(t, "kt_"+name))
		opts.Profile = name
		if err := Run(context.Background(), opts); err != nil {
			t.Fatal(err)
		}
	}
	callsBefore := len(h.calls)

	if _, err := LoadInventory(); err != nil {
		t.Fatalf("LoadInventory() error = %v", err)
	}
	for _, call := range h.calls[callsBefore:] {
		if call.name == "security" {
			t.Errorf("LoadInventory() invoked security: %v", call.args)
		}
	}
}

func TestInventoryWriteJSONIsMachineReadable(t *testing.T) {
	h := profileHarness(t)
	opts := h.options("kt_staging", pingServer(t, "kt_staging"))
	opts.Profile = "staging"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}
	inventory, err := LoadInventory()
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := inventory.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON() error = %v", err)
	}
	var decoded Inventory
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("emitted JSON does not round-trip: %v\n%s", err, buf.String())
	}
	if decoded.Active != "staging" {
		t.Errorf("decoded Active = %q, want staging", decoded.Active)
	}
	if len(decoded.Profiles) != 1 || !decoded.Profiles[0].Active {
		t.Errorf("decoded Profiles = %+v", decoded.Profiles)
	}
}

// Table rows must all carry the same cell count, otherwise tabwriter cannot
// align the columns and the listing reads as garbled.
func TestInventoryWriteTextAlignsRowsWithBrokenProfiles(t *testing.T) {
	h := profileHarness(t)
	opts := h.options("kt_staging", pingServer(t, "kt_staging"))
	opts.Profile = "staging"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.Create("halfway"); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}
	inventory, err := LoadInventory()
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := inventory.WriteText(&buf); err != nil {
		t.Fatalf("WriteText() error = %v", err)
	}
	output := buf.String()

	// Match only table rows. The per-profile explanation printed below the table
	// also mentions the profile name and would otherwise be picked up here.
	var header string
	rows := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		switch {
		case strings.Contains(line, "NAME") && strings.Contains(line, "BACKEND"):
			header = line
		case strings.Contains(line, "halfway") && strings.Contains(line, "(unusable)"):
			rows["halfway"] = line
		case strings.Contains(line, "staging") && strings.Contains(line, "http"):
			rows["staging"] = line
		}
	}
	if header == "" {
		t.Fatalf("no header row in output:\n%s", output)
	}
	nameColumn := strings.Index(header, "NAME")
	for name, row := range rows {
		if len(row) <= nameColumn || row[nameColumn:nameColumn+len(name)] != name {
			t.Errorf("row %q does not start its name at the NAME column %d:\n%s", name, nameColumn, output)
		}
	}
	// The active profile is marked, and the broken one explains itself.
	if !strings.Contains(output, "*") {
		t.Errorf("no active marker in output:\n%s", output)
	}
	if !strings.Contains(output, "halfway: not set up yet") {
		t.Errorf("broken profile detail missing:\n%s", output)
	}
}

func TestInventoryWriteTextPointsLegacyInstallAtMigrate(t *testing.T) {
	h := profileHarness(t)
	if err := Run(context.Background(), h.options("kt_legacy", pingServer(t, "kt_legacy"))); err != nil {
		t.Fatal(err)
	}
	inventory, err := LoadInventory()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := inventory.WriteText(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "kontext profile migrate") {
		t.Errorf("legacy listing does not mention migrate:\n%s", buf.String())
	}
}

func TestRemoveProfileDeletesDataAndToken(t *testing.T) {
	h := switchHarness(t)
	dir, err := profile.Dir("staging")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer

	if err := RemoveProfile(context.Background(), "staging", &out); err != nil {
		t.Fatalf("RemoveProfile() error = %v", err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Errorf("profile directory survived removal (err = %v)", err)
	}
	if _, ok := h.keychain["kontext-install-token.staging"]; ok {
		t.Error("keychain item survived profile removal")
	}
}

// Removing the active profile would leave the pointer aimed at nothing.
func TestRemoveProfileRefusesActive(t *testing.T) {
	h := switchHarness(t)
	var out bytes.Buffer
	if err := RemoveProfile(context.Background(), "prod", &out); err == nil {
		t.Fatal("RemoveProfile() on the active profile = nil, want error")
	}
	if _, ok := h.keychain["kontext-install-token.prod"]; !ok {
		t.Error("RemoveProfile() deleted the token after refusing to remove the profile")
	}
	dir, err := profile.Dir("prod")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "managed.json")); err != nil {
		t.Errorf("RemoveProfile() removed data after refusing: %v", err)
	}
}
