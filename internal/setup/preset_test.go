package setup

import (
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/profile"
)

func TestPresetsResolveKnownEnvironments(t *testing.T) {
	cases := []struct {
		name     string
		url      string
		loopback bool
	}{
		{"prod", DefaultCloudURL, false},
		{"production", DefaultCloudURL, false},
		{"staging", StagingCloudURL, false},
		{"stg", StagingCloudURL, false},
		{"local", LocalCloudURL, true},
		{"localdev", LocalCloudURL, true},
		{"dev", LocalCloudURL, true},
	}
	for _, c := range cases {
		preset, ok := LookupPreset(c.name)
		if !ok {
			t.Errorf("LookupPreset(%q) not found", c.name)
			continue
		}
		if preset.CloudURL != c.url {
			t.Errorf("LookupPreset(%q).CloudURL = %q, want %q", c.name, preset.CloudURL, c.url)
		}
		if preset.AllowHTTPLoopback != c.loopback {
			t.Errorf("LookupPreset(%q).AllowHTTPLoopback = %v, want %v", c.name, preset.AllowHTTPLoopback, c.loopback)
		}
		if preset.Description == "" {
			t.Errorf("LookupPreset(%q) has no description to print", c.name)
		}
	}
}

// Only local presets carry the plaintext opt-in. A preset that quietly enabled it
// for a hosted endpoint would be the exact footgun the opt-in exists to prevent.
func TestOnlyLocalPresetsEnableLoopbackHTTP(t *testing.T) {
	for _, name := range PresetNames() {
		preset, ok := LookupPreset(name)
		if !ok {
			t.Fatalf("PresetNames() lists %q but LookupPreset does not know it", name)
		}
		isLocal := strings.Contains(preset.CloudURL, "localhost") ||
			strings.Contains(preset.CloudURL, "127.0.0.1")
		if preset.AllowHTTPLoopback != isLocal {
			t.Errorf("preset %q: AllowHTTPLoopback = %v for URL %q", name, preset.AllowHTTPLoopback, preset.CloudURL)
		}
		if !isLocal && !strings.HasPrefix(preset.CloudURL, "https://") {
			t.Errorf("preset %q: hosted endpoint %q is not https", name, preset.CloudURL)
		}
	}
}

// An unknown name must fall through so arbitrary profile names still work — the
// presets are a convenience, not a whitelist.
func TestUnknownNamesHaveNoPreset(t *testing.T) {
	for _, name := range []string{"acme", "wk2", "hasan-test", "", "PRODUCTIONISH"} {
		if _, ok := LookupPreset(name); ok {
			t.Errorf("LookupPreset(%q) unexpectedly matched", name)
		}
	}
}

func TestPresetLookupIsCaseAndSpaceInsensitive(t *testing.T) {
	for _, name := range []string{"PROD", "Prod", "  staging  ", "LocalDev"} {
		if _, ok := LookupPreset(name); !ok {
			t.Errorf("LookupPreset(%q) not found", name)
		}
	}
}

// Every preset URL must survive the validation that setup applies, or `profile
// add <name>` would fail on a value we supplied ourselves.
func TestPresetURLsPassCloudURLValidation(t *testing.T) {
	t.Setenv("KONTEXT_MANAGED_ALLOW_HTTP_LOCALHOST", "")
	for _, name := range PresetNames() {
		preset, _ := LookupPreset(name)
		if err := validatePresetURL(preset); err != nil {
			t.Errorf("preset %q (%s): %v", name, preset.CloudURL, err)
		}
	}
}

func TestPresetNamesAreAllResolvable(t *testing.T) {
	if len(PresetNames()) == 0 {
		t.Fatal("PresetNames() is empty")
	}
	for _, name := range PresetNames() {
		if _, ok := LookupPreset(name); !ok {
			t.Errorf("PresetNames() lists %q which LookupPreset rejects", name)
		}
	}
}

// Consumers group profiles by environment; the mapping from URL to environment
// is knowledge this package already has, so it answers rather than making every
// consumer hardcode the same three URLs.
func TestEnvironmentForClassifiesKnownBackends(t *testing.T) {
	cases := map[string]string{
		DefaultCloudURL:          EnvironmentProduction,
		StagingCloudURL:          EnvironmentStaging,
		LocalCloudURL:            EnvironmentLocal,
		"http://localhost:9999":  EnvironmentLocal,
		"http://127.0.0.1:4000":  EnvironmentLocal,
		"https://LOCALHOST:8443": EnvironmentLocal,
	}
	for url, want := range cases {
		if got := EnvironmentFor(url); got != want {
			t.Errorf("EnvironmentFor(%q) = %q, want %q", url, got, want)
		}
	}
}

// A self-hosted or one-off endpoint is legitimate. Forcing it into a bucket
// would mislabel it; empty lets a consumer show it as itself.
func TestEnvironmentForLeavesUnknownBackendsUnclassified(t *testing.T) {
	for _, url := range []string{"", "https://api.acme.example", "https://api.eu.kontext.security", "not a url"} {
		if got := EnvironmentFor(url); got != "" {
			t.Errorf("EnvironmentFor(%q) = %q, want empty", url, got)
		}
	}
}

// The name is only a handle, so it can be derived once the workspace is known —
// which is the whole reason `profile add` no longer requires one.
func TestDeriveProfileNameUsesTheEnvironmentWhenFree(t *testing.T) {
	withProfileRoot(t)
	for url, want := range map[string]string{
		DefaultCloudURL: "prod",
		StagingCloudURL: "staging",
		LocalCloudURL:   "local",
	} {
		got, err := DeriveProfileName(url, "Acme Corp", "org_1")
		if err != nil {
			t.Fatalf("DeriveProfileName(%q) error = %v", url, err)
		}
		if got != want {
			t.Errorf("DeriveProfileName(%q) = %q, want %q", url, got, want)
		}
	}
}

// A second workspace on the same backend qualifies the name rather than failing:
// several workspaces per environment is the supported case.
func TestDeriveProfileNameQualifiesWhenTheEnvironmentIsTaken(t *testing.T) {
	withProfileRoot(t)
	if _, err := profile.Create("staging"); err != nil {
		t.Fatal(err)
	}
	got, err := DeriveProfileName(StagingCloudURL, "Acme Corp", "org_1")
	if err != nil {
		t.Fatal(err)
	}
	if got != "staging-acme-corp" {
		t.Errorf("DeriveProfileName() = %q, want staging-acme-corp", got)
	}
}

// Every derived name must satisfy the same validator a typed one does — it
// becomes a directory and a keychain suffix either way.
func TestDerivedNamesAreAlwaysValid(t *testing.T) {
	withProfileRoot(t)
	for _, org := range []string{
		"Kontext's Workspace", "ACME  CORP!!", "—", "ünïcødé wörk", "a", "",
		strings.Repeat("very long workspace name ", 5),
	} {
		name, err := DeriveProfileName(StagingCloudURL, org, "org_1")
		if err != nil {
			t.Fatalf("DeriveProfileName(%q) error = %v", org, err)
		}
		if err := profile.ValidateName(name); err != nil {
			t.Errorf("derived %q from %q, which is not a valid profile name: %v", name, org, err)
		}
		if _, err := profile.Create(name); err != nil {
			t.Fatalf("derived name %q collided: %v", name, err)
		}
	}
}

// An unknown backend still gets a usable name rather than an error.
func TestDeriveProfileNameHandlesAnUnknownBackend(t *testing.T) {
	withProfileRoot(t)
	name, err := DeriveProfileName("https://api.acme.example", "Acme", "org_1")
	if err != nil {
		t.Fatal(err)
	}
	if name != "workspace" {
		t.Errorf("DeriveProfileName() = %q, want workspace", name)
	}
}

func withProfileRoot(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv(profile.EnvRoot, "")
}
