package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

// profileHarness is newHarness plus a profile root that follows the fake HOME.
// The loopback escape hatch is on because every Run here pings an httptest
// server over plain http.
func profileHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	t.Setenv(profile.EnvRoot, "")
	allowLoopback(t)
	return h
}

func kontextRoot(home string) string {
	return filepath.Join(home, "Library", "Application Support", "Kontext")
}

// A machine that has never used profiles must keep resolving the exact paths
// and keychain item it always did — that is what makes this change additive.
func TestResolveTargetWithoutProfilesIsLegacy(t *testing.T) {
	h := profileHarness(t)
	slot, err := resolveTarget("")
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	if slot.Profile != "" {
		t.Errorf("Profile = %q, want empty", slot.Profile)
	}
	if want := filepath.Join(kontextRoot(h.home), "managed.json"); slot.ConfigPath != want {
		t.Errorf("ConfigPath = %q, want %q", slot.ConfigPath, want)
	}
	if want := filepath.Join(kontextRoot(h.home), "installation.json"); slot.IdentityPath != want {
		t.Errorf("IdentityPath = %q, want %q", slot.IdentityPath, want)
	}
	if slot.KeychainItem != KeychainItemName {
		t.Errorf("KeychainItem = %q, want %q", slot.KeychainItem, KeychainItemName)
	}
}

func TestResolveTargetFollowsActiveProfile(t *testing.T) {
	h := profileHarness(t)
	if _, err := profile.Create("staging"); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}
	slot, err := resolveTarget("")
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	base := filepath.Join(kontextRoot(h.home), "profiles", "staging")
	if slot.Profile != "staging" {
		t.Errorf("Profile = %q, want %q", slot.Profile, "staging")
	}
	if want := filepath.Join(base, "managed.json"); slot.ConfigPath != want {
		t.Errorf("ConfigPath = %q, want %q", slot.ConfigPath, want)
	}
	if want := "kontext-install-token.staging"; slot.KeychainItem != want {
		t.Errorf("KeychainItem = %q, want %q", slot.KeychainItem, want)
	}
}

// An explicit name outranks the active pointer — this is how `profile add`
// writes a profile that is not (yet) active.
func TestResolveTargetExplicitNameOverridesActive(t *testing.T) {
	profileHarness(t)
	for _, name := range []string{"prod", "staging"} {
		if _, err := profile.Create(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := profile.SetActive("prod"); err != nil {
		t.Fatal(err)
	}
	slot, err := resolveTarget("staging")
	if err != nil {
		t.Fatalf("resolveTarget() error = %v", err)
	}
	if slot.Profile != "staging" {
		t.Fatalf("Profile = %q, want %q", slot.Profile, "staging")
	}
}

func TestResolveTargetRejectsInvalidName(t *testing.T) {
	profileHarness(t)
	if _, err := resolveTarget("../escape"); err == nil {
		t.Fatal("resolveTarget() with traversal = nil, want error")
	}
}

// Setup into a named profile must write that profile's config, identity, and
// keychain item — and the config's token ref must name the item setup actually
// wrote, or the daemon dies under launchd with nothing but "not running".
func TestRunWritesProfileScopedState(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_profile_token")
	opts := h.options("kt_profile_token", server)
	opts.Profile = "staging"

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() error = %v\nstdout:\n%s\nstderr:\n%s", err, h.out.String(), h.errOut.String())
	}

	base := filepath.Join(kontextRoot(h.home), "profiles", "staging")
	loaded, err := managedconfig.LoadFile(filepath.Join(base, "managed.json"))
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if got, want := loaded.Config.Credentials.InstallTokenRef.Name, "kontext-install-token.staging"; got != want {
		t.Errorf("token ref = %q, want %q", got, want)
	}
	if got := h.keychain["kontext-install-token.staging"]; got != "kt_profile_token" {
		t.Errorf("keychain[kontext-install-token.staging] = %q, want the install token", got)
	}
	if _, err := installation.LoadFile(filepath.Join(base, "installation.json")); err != nil {
		t.Errorf("profile installation identity: %v", err)
	}

	// The legacy slot must be untouched by a profile-targeted run.
	if _, err := os.Lstat(filepath.Join(kontextRoot(h.home), "managed.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("legacy managed.json exists after a profile-targeted setup (err = %v)", err)
	}
}

// Two profiles must end up with independent configs, tokens, and identities.
func TestRunKeepsTwoProfilesIndependent(t *testing.T) {
	h := profileHarness(t)

	prodServer := pingServer(t, "kt_prod")
	prodOpts := h.options("kt_prod", prodServer)
	prodOpts.Profile = "prod"
	if err := Run(context.Background(), prodOpts); err != nil {
		t.Fatalf("Run(prod) error = %v", err)
	}

	stagingServer := pingServer(t, "kt_staging")
	stagingOpts := h.options("kt_staging", stagingServer)
	stagingOpts.Profile = "staging"
	if err := Run(context.Background(), stagingOpts); err != nil {
		t.Fatalf("Run(staging) error = %v", err)
	}

	if h.keychain["kontext-install-token.prod"] != "kt_prod" {
		t.Errorf("prod token = %q, want kt_prod", h.keychain["kontext-install-token.prod"])
	}
	if h.keychain["kontext-install-token.staging"] != "kt_staging" {
		t.Errorf("staging token = %q, want kt_staging", h.keychain["kontext-install-token.staging"])
	}

	base := filepath.Join(kontextRoot(h.home), "profiles")
	prodCfg, err := managedconfig.LoadFile(filepath.Join(base, "prod", "managed.json"))
	if err != nil {
		t.Fatal(err)
	}
	stagingCfg, err := managedconfig.LoadFile(filepath.Join(base, "staging", "managed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if prodCfg.Config.CloudURL == stagingCfg.Config.CloudURL {
		t.Errorf("both profiles point at %q; expected distinct backends", prodCfg.Config.CloudURL)
	}

	prodID, err := installation.LoadFile(filepath.Join(base, "prod", "installation.json"))
	if err != nil {
		t.Fatal(err)
	}
	stagingID, err := installation.LoadFile(filepath.Join(base, "staging", "installation.json"))
	if err != nil {
		t.Fatal(err)
	}
	if prodID.InstallationID == stagingID.InstallationID {
		t.Errorf("both profiles share installation id %q", prodID.InstallationID)
	}
}

// Re-running setup for an existing profile rotates its token in place.
func TestRunIntoExistingProfileRotatesToken(t *testing.T) {
	h := profileHarness(t)
	first := pingServer(t, "kt_first")
	opts := h.options("kt_first", first)
	opts.Profile = "staging"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	second := pingServer(t, "kt_second")
	opts2 := h.options("kt_second", second)
	opts2.Profile = "staging"
	if err := Run(context.Background(), opts2); err != nil {
		t.Fatalf("Run() rerun error = %v", err)
	}
	if got := h.keychain["kontext-install-token.staging"]; got != "kt_second" {
		t.Errorf("token after rotation = %q, want kt_second", got)
	}
}

// The whole point of the durable opt-in: a local-dev profile written with
// --allow-http-loopback is readable with NO environment variable set, which is
// the situation the background agent under launchd is always in. Before this,
// such a config parsed in the terminal and was rejected by the daemon.
func TestRunWritesLoopbackOptInThatReadsWithoutEnv(t *testing.T) {
	h := profileHarness(t)
	// Explicitly drop the ambient escape hatch that profileHarness sets, so this
	// exercises the config field alone.
	t.Setenv(managedconfig.EnvAllowHTTP, "")

	server := pingServer(t, "kt_local")
	opts := h.options("kt_local", server)
	opts.Profile = "localdev"
	opts.AllowHTTPLoopback = true

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() error = %v\nstdout:\n%s\nstderr:\n%s", err, h.out.String(), h.errOut.String())
	}

	configPath := filepath.Join(kontextRoot(h.home), "profiles", "localdev", "managed.json")
	loaded, err := managedconfig.LoadFile(configPath)
	if err != nil {
		t.Fatalf("LoadFile() error = %v — the daemon would reject this config", err)
	}
	if !loaded.Config.AllowHTTPLoopback {
		t.Error("allow_http_loopback was not persisted")
	}
	if !strings.HasPrefix(loaded.Config.CloudURL, "http://127.0.0.1") {
		t.Errorf("cloud_url = %q, want the loopback test server", loaded.Config.CloudURL)
	}

	// And the switch path — which validates the config the same way the daemon
	// does — must accept it too.
	if err := verifyProfileUsable(context.Background(), "localdev"); err != nil {
		t.Errorf("verifyProfileUsable() = %v, want nil", err)
	}
}

// Without the flag, a plaintext local URL fails at setup time rather than being
// written and failing later inside the daemon.
func TestRunRejectsLoopbackHTTPWithoutOptIn(t *testing.T) {
	h := profileHarness(t)
	t.Setenv(managedconfig.EnvAllowHTTP, "")

	server := pingServer(t, "kt_local")
	opts := h.options("kt_local", server)
	opts.Profile = "localdev"
	opts.AllowHTTPLoopback = false

	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run() = nil error, want rejection of plaintext http without the opt-in")
	}
	if !strings.Contains(err.Error(), "allow_http_loopback") {
		t.Fatalf("error = %v, want it to name the flag", err)
	}
	// Nothing may be left behind by a refused setup.
	if _, statErr := os.Lstat(filepath.Join(kontextRoot(h.home), "profiles", "localdev")); statErr == nil {
		t.Error("a refused setup created the profile directory")
	}
}

// A normal https profile must not carry the field at all, so production configs
// stay byte-identical to what they were before it existed.
func TestRunOmitsLoopbackOptInForHTTPSProfiles(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_prod")
	opts := h.options("kt_prod", server)
	opts.Profile = "prod"

	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(kontextRoot(h.home), "profiles", "prod", "managed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "allow_http_loopback") {
		t.Errorf("config mentions allow_http_loopback without the flag:\n%s", data)
	}
}

func TestMigrateLegacyInstallIsNoOpWithoutLegacyState(t *testing.T) {
	profileHarness(t)
	migrated, err := MigrateLegacyInstall(context.Background(), nil)
	if err != nil {
		t.Fatalf("MigrateLegacyInstall() error = %v", err)
	}
	if migrated {
		t.Fatal("MigrateLegacyInstall() = true on a machine with no legacy state")
	}
}

// The core migration: a legacy install becomes profile "default", the state
// MOVES (legacy paths end up empty), and the keychain is never touched.
func TestMigrateLegacyInstallMovesStateIntoDefault(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_legacy")
	if err := Run(context.Background(), h.options("kt_legacy", server)); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	root := kontextRoot(h.home)
	// Simulate the ledger cache the daemon would have created.
	observeDir := filepath.Join(root, "managed-observe")
	if err := os.MkdirAll(observeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"guard.db", "guard.db-wal", "stream-state.json"} {
		if err := os.WriteFile(filepath.Join(observeDir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	callsBefore := len(h.calls)

	migrated, err := MigrateLegacyInstall(context.Background(), nil)
	if err != nil {
		t.Fatalf("MigrateLegacyInstall() error = %v", err)
	}
	if !migrated {
		t.Fatal("MigrateLegacyInstall() = false, want true")
	}

	if name, err := profile.ActiveName(); err != nil || name != profile.DefaultName {
		t.Fatalf("ActiveName() = %q, %v; want %q", name, err, profile.DefaultName)
	}

	base := filepath.Join(root, "profiles", profile.DefaultName)
	for _, name := range []string{"managed.json", "installation.json"} {
		if _, err := os.Lstat(filepath.Join(base, name)); err != nil {
			t.Errorf("%s did not move into the profile: %v", name, err)
		}
		if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s still present at the legacy path (err = %v)", name, err)
		}
	}
	// The whole ledger directory moves, siblings included, so the export cursor
	// travels with its database.
	for _, name := range []string{"guard.db", "guard.db-wal", "stream-state.json"} {
		if _, err := os.Lstat(filepath.Join(base, "managed-observe", name)); err != nil {
			t.Errorf("managed-observe/%s did not move: %v", name, err)
		}
	}
	if _, err := os.Lstat(observeDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("legacy managed-observe still present (err = %v)", err)
	}

	// The migrated config keeps naming the legacy keychain item, so migration
	// performs no keychain work at all.
	loaded, err := managedconfig.LoadFile(filepath.Join(base, "managed.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Config.Credentials.InstallTokenRef.Name; got != KeychainItemName {
		t.Errorf("migrated token ref = %q, want the legacy item %q", got, KeychainItemName)
	}
	for _, call := range h.calls[callsBefore:] {
		if call.name == "security" {
			t.Errorf("migration touched the keychain: security %v", call.args)
		}
	}
}

// Cached model weights are machine-scoped and can be hundreds of megabytes.
// Migration must hoist them OUT of the ledger directory it moves, or they end up
// stranded inside one profile where nothing looks for them — and the next
// profile silently re-downloads them.
func TestMigrateLegacyInstallHoistsModelCacheToSharedRoot(t *testing.T) {
	h := profileHarness(t)
	if err := Run(context.Background(), h.options("kt_legacy", pingServer(t, "kt_legacy"))); err != nil {
		t.Fatal(err)
	}
	root := kontextRoot(h.home)
	cacheDir := filepath.Join(root, profile.ManagedObserveDir, profile.ModelCacheDirName)
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	weights := filepath.Join(cacheDir, "model.gguf")
	if err := os.WriteFile(weights, []byte("pretend-weights"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := MigrateLegacyInstall(context.Background(), nil); err != nil {
		t.Fatalf("MigrateLegacyInstall() error = %v", err)
	}

	// It landed at the shared root, with its contents.
	hoisted := filepath.Join(root, profile.ModelCacheDirName, "model.gguf")
	data, err := os.ReadFile(hoisted)
	if err != nil {
		t.Fatalf("model cache was not hoisted to the shared root: %v", err)
	}
	if string(data) != "pretend-weights" {
		t.Errorf("hoisted cache contents = %q", data)
	}
	// And it is NOT inside the profile.
	stranded := filepath.Join(root, "profiles", profile.DefaultName, profile.ManagedObserveDir, profile.ModelCacheDirName)
	if _, err := os.Lstat(stranded); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("model cache is stranded inside the profile (err = %v)", err)
	}
	// The ledger itself still moved into the profile.
	if _, err := os.Lstat(filepath.Join(root, "profiles", profile.DefaultName, profile.ManagedObserveDir)); err != nil {
		t.Errorf("ledger directory did not move into the profile: %v", err)
	}
}

// No cache is the normal case (the guardrail LLM is optional) and must not fail.
func TestMigrateLegacyInstallWithoutModelCache(t *testing.T) {
	h := profileHarness(t)
	if err := Run(context.Background(), h.options("kt_legacy", pingServer(t, "kt_legacy"))); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateLegacyInstall(context.Background(), nil)
	if err != nil || !migrated {
		t.Fatalf("MigrateLegacyInstall() = %v, %v", migrated, err)
	}
}

// Migration must stop the daemon before moving the database and start it after.
func TestMigrateLegacyInstallStopsAndRestartsAgent(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_legacy")
	if err := Run(context.Background(), h.options("kt_legacy", server)); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	plist := filepath.Join(h.home, "Library", "LaunchAgents", LaunchAgentLabel+".plist")
	if _, err := os.Lstat(plist); err != nil {
		t.Fatalf("expected setup to install a plist: %v", err)
	}
	callsBefore := len(h.calls)

	if _, err := MigrateLegacyInstall(context.Background(), nil); err != nil {
		t.Fatalf("MigrateLegacyInstall() error = %v", err)
	}

	var order []string
	for _, call := range h.calls[callsBefore:] {
		if call.name != "launchctl" || len(call.args) == 0 {
			continue
		}
		if call.args[0] == "bootout" || call.args[0] == "bootstrap" {
			order = append(order, call.args[0])
		}
	}
	if len(order) < 2 || order[0] != "bootout" || order[len(order)-1] != "bootstrap" {
		t.Fatalf("launchctl order = %v, want bootout before bootstrap", order)
	}
}

func TestMigrateLegacyInstallIsIdempotent(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_legacy")
	if err := Run(context.Background(), h.options("kt_legacy", server)); err != nil {
		t.Fatal(err)
	}
	if migrated, err := MigrateLegacyInstall(context.Background(), nil); err != nil || !migrated {
		t.Fatalf("first MigrateLegacyInstall() = %v, %v", migrated, err)
	}
	migrated, err := MigrateLegacyInstall(context.Background(), nil)
	if err != nil {
		t.Fatalf("second MigrateLegacyInstall() error = %v", err)
	}
	if migrated {
		t.Fatal("second MigrateLegacyInstall() = true, want false")
	}
}

// A default/ directory with no pointer at it is a state this code never
// produces; merging into it could pair one workspace's config with another's
// ledger, so it must refuse.
func TestMigrateLegacyInstallRefusesExistingDefaultProfile(t *testing.T) {
	h := profileHarness(t)
	server := pingServer(t, "kt_legacy")
	if err := Run(context.Background(), h.options("kt_legacy", server)); err != nil {
		t.Fatal(err)
	}
	if _, err := profile.Create(profile.DefaultName); err != nil {
		t.Fatal(err)
	}
	_, err := MigrateLegacyInstall(context.Background(), nil)
	if err == nil {
		t.Fatal("MigrateLegacyInstall() = nil error, want refusal")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error = %v, want an 'already exists' refusal", err)
	}
}

// Uninstall must clear every profile's token, not only the active profile's.
func TestUninstallRemovesEveryProfileToken(t *testing.T) {
	h := profileHarness(t)
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

	if err := Uninstall(context.Background(), h.options("", pingServer(t, "unused"))); err != nil {
		t.Fatalf("Uninstall() error = %v\nstdout:\n%s", err, h.out.String())
	}

	for _, item := range []string{"kontext-install-token.prod", "kontext-install-token.staging"} {
		if _, ok := h.keychain[item]; ok {
			t.Errorf("keychain item %q survived uninstall", item)
		}
	}
	base := filepath.Join(kontextRoot(h.home), "profiles")
	for _, name := range []string{"prod", "staging"} {
		if _, err := os.Lstat(filepath.Join(base, name, "managed.json")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s managed.json survived uninstall (err = %v)", name, err)
		}
	}
	// The pointer is cleared so resolution returns to the legacy paths.
	if _, err := profile.ActiveName(); !errors.Is(err, profile.ErrNoActive) {
		t.Errorf("ActiveName() after uninstall = %v, want ErrNoActive", err)
	}
}
