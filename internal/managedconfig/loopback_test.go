package managedconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loopbackConfigJSON(t *testing.T, cloudURL string, allow bool) []byte {
	t.Helper()
	cfg := map[string]any{
		"version":   Version,
		"cloud_url": cloudURL,
		"mode":      ModeRemote,
		"agent":     Agent,
		"credentials": map[string]any{
			"install_token_ref": "keychain:kontext-install-token",
		},
	}
	if allow {
		cfg["allow_http_loopback"] = true
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The point of the config field: a loopback http backend parses with NO
// environment variable set, so the daemon under launchd reads it the same way
// the terminal does.
func TestParseAcceptsLoopbackHTTPFromConfigWithoutEnv(t *testing.T) {
	t.Setenv(EnvAllowHTTP, "")
	for _, url := range []string{
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	} {
		cfg, err := Parse(loopbackConfigJSON(t, url, true))
		if err != nil {
			t.Errorf("Parse(%q) error = %v, want nil", url, err)
			continue
		}
		if !cfg.AllowHTTPLoopback {
			t.Errorf("Parse(%q) lost allow_http_loopback", url)
		}
		if cfg.CloudURL != url {
			t.Errorf("Parse(%q) cloud_url = %q", url, cfg.CloudURL)
		}
	}
}

// Without the opt-in (and without the env var) plaintext is still refused, and
// the message names the flag that fixes it.
func TestParseRejectsLoopbackHTTPWithoutOptIn(t *testing.T) {
	t.Setenv(EnvAllowHTTP, "")
	_, err := Parse(loopbackConfigJSON(t, "http://localhost:8080", false))
	if err == nil {
		t.Fatal("Parse() = nil error, want rejection")
	}
	if !strings.Contains(err.Error(), "allow_http_loopback") {
		t.Errorf("error = %v, want it to name allow_http_loopback", err)
	}
}

// The hard boundary: the opt-in widens the SCHEME for loopback only. It must
// never make plaintext acceptable to a host that can leave the machine.
func TestOptInNeverAllowsPlaintextToRemoteHosts(t *testing.T) {
	t.Setenv(EnvAllowHTTP, "")
	for _, url := range []string{
		"http://api.kontext.security",
		"http://evil.example.com:8080",
		"http://10.0.0.5:8080",
		"http://192.168.1.10:8080",
		"http://169.254.169.254",
		"http://0.0.0.0:8080",
	} {
		if _, err := Parse(loopbackConfigJSON(t, url, true)); err == nil {
			t.Errorf("Parse(%q) with allow_http_loopback = nil error, want rejection", url)
		}
	}
}

// The original ambient escape hatch keeps working, so existing local-dev setups
// are not broken by the durable form being added.
func TestEnvEscapeHatchStillWorks(t *testing.T) {
	t.Setenv(EnvAllowHTTP, "1")
	if _, err := Parse(loopbackConfigJSON(t, "http://localhost:8080", false)); err != nil {
		t.Fatalf("Parse() with the env hatch error = %v, want nil", err)
	}
}

// A production config must be byte-identical to what it was before this field
// existed, so the field is omitted when false.
func TestConfigOmitsAllowHTTPLoopbackWhenFalse(t *testing.T) {
	cfg := Config{
		Version:  Version,
		CloudURL: "https://api.kontext.security",
		Mode:     ModeRemote,
		Agent:    Agent,
		Credentials: Credentials{
			InstallTokenRef: TokenRef{Source: "keychain", Name: "kontext-install-token"},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "allow_http_loopback") {
		t.Fatalf("https config mentions allow_http_loopback: %s", data)
	}

	cfg.AllowHTTPLoopback = true
	data, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"allow_http_loopback":true`) {
		t.Fatalf("opted-in config missing the field: %s", data)
	}
}

// An MDM deployment streaming governance records in plaintext to something on
// localhost is never intended; Load refuses it rather than serving it.
func TestLoadRefusesLoopbackOptInInSystemConfig(t *testing.T) {
	t.Setenv(EnvAllowHTTP, "")
	t.Setenv(EnvPath, "")
	dir := t.TempDir()
	system := filepath.Join(dir, "managed.json")
	if err := os.WriteFile(system, loopbackConfigJSON(t, "http://localhost:8080", true), 0o600); err != nil {
		t.Fatal(err)
	}
	systemPath = system
	t.Cleanup(func() { systemPath = DefaultPath })

	_, err := Load()
	if err == nil {
		t.Fatal("Load() = nil error, want refusal for a system-scope opt-in")
	}
	if !strings.Contains(err.Error(), "organization-managed") {
		t.Fatalf("error = %v, want it to explain the scope refusal", err)
	}
}

// The same opt-in is fine at user scope, which is where local development lives.
func TestLoadAcceptsLoopbackOptInAtUserScope(t *testing.T) {
	t.Setenv(EnvAllowHTTP, "")
	t.Setenv(EnvPath, "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	systemPath = filepath.Join(t.TempDir(), "absent.json")
	t.Cleanup(func() { systemPath = DefaultPath })

	userPath := LegacyUserPath()
	if err := os.MkdirAll(filepath.Dir(userPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userPath, loopbackConfigJSON(t, "http://localhost:8080", true), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if loaded.Scope != ScopeUser {
		t.Fatalf("Scope = %q, want %q", loaded.Scope, ScopeUser)
	}
	if !loaded.Config.AllowHTTPLoopback {
		t.Error("AllowHTTPLoopback = false, want true")
	}
}

func TestValidateCloudURLHonorsTheFlagArgument(t *testing.T) {
	t.Setenv(EnvAllowHTTP, "")
	if err := ValidateCloudURL("http://localhost:8080", true); err != nil {
		t.Errorf("ValidateCloudURL(loopback, true) = %v, want nil", err)
	}
	if err := ValidateCloudURL("http://localhost:8080", false); err == nil {
		t.Error("ValidateCloudURL(loopback, false) = nil, want error")
	}
	// The flag is a no-op for https rather than an error — passing it with a
	// normal backend should not fail a setup run.
	if err := ValidateCloudURL("https://api.kontext.security", true); err != nil {
		t.Errorf("ValidateCloudURL(https, true) = %v, want nil", err)
	}
}
