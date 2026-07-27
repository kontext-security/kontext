package managedconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFileMissingReturnsErrNotManaged(t *testing.T) {
	_, err := LoadFile(filepath.Join(t.TempDir(), "missing.json"))
	if !errors.Is(err, ErrNotManaged) {
		t.Fatalf("LoadFile() error = %v, want ErrNotManaged", err)
	}
}

func TestParseValidConfigNormalizesStrings(t *testing.T) {
	cfg, err := Parse([]byte(`{
  "version": " managed-install-v1 ",
  "cloud_url": " https://api.kontext.dev ",
  "mode": " observe ",
  "agent": " claude ",
  "credentials": {
    "install_token_ref": " keychain:kontext-managed-install-token "
  },
  "device": {
    "label": " Engineering Mac ",
    "user_email": " Anna@Katana.com "
  }
}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Version != Version || cfg.CloudURL != "https://api.kontext.dev" {
		t.Fatalf("config not normalized: %+v", cfg)
	}
	if got := cfg.Credentials.InstallTokenRef; got.Source != "keychain" || got.Name != "kontext-managed-install-token" {
		t.Fatalf("token ref = %+v", got)
	}
	if cfg.Device.Label != "Engineering Mac" {
		t.Fatalf("device label = %q", cfg.Device.Label)
	}
	// Trimmed but not lowercased — normalization to lowercase happens at ingest.
	if cfg.Device.UserEmail != "Anna@Katana.com" {
		t.Fatalf("device user_email = %q", cfg.Device.UserEmail)
	}
}

func TestParseIgnoresLegacyOrganizationID(t *testing.T) {
	input := strings.Replace(validConfigJSON(), `"cloud_url":`, `"organization_id": "org_123",
  "cloud_url":`, 1)
	if _, err := Parse([]byte(input)); err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
}

func TestParseAcceptsLegacyCoworkEnabled(t *testing.T) {
	input := strings.Replace(validConfigJSON(), `"cloud_url":`, `"cowork_enabled": true,
  "cloud_url":`, 1)
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !cfg.LegacyCoworkEnabled {
		t.Fatal("LegacyCoworkEnabled = false, want true")
	}
}

func TestParseModeObserveAndEnforce(t *testing.T) {
	cfg, err := Parse([]byte(strings.Replace(validConfigJSON(), `"mode": "observe"`, `"mode": "enforce"`, 1)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Mode != ModeEnforce {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeEnforce)
	}
	if _, err := Parse([]byte(strings.Replace(validConfigJSON(), `"mode": "observe"`, `"mode": "block"`, 1))); err == nil {
		t.Fatal("Parse() accepted unknown mode")
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	_, err := Parse([]byte(`{
  "version": "managed-install-v1",
  "cloud_url": "https://api.kontext.dev",
  "mode": "observe",
  "agent": "claude",
  "credentials": {"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"},
  "extra": true
}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Parse() error = %v, want unknown field", err)
	}
}

func TestParseRejectsTrailingJSON(t *testing.T) {
	_, err := Parse([]byte(validConfigJSON() + `{}`))
	if err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("Parse() error = %v, want trailing JSON", err)
	}
}

func TestParseRequiresFields(t *testing.T) {
	tests := map[string]string{
		"version":           `"version": ""`,
		"cloud_url":         `"cloud_url": ""`,
		"mode":              `"mode": ""`,
		"agent":             `"agent": ""`,
		"install_token_ref": `"install_token_ref": ""`,
	}
	for name, replacement := range tests {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(validConfigJSON(), replacementFor(name), replacement, 1)
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatalf("Parse() error = nil, want failure")
			}
		})
	}
}

func TestParseRejectsInvalidCloudURL(t *testing.T) {
	tests := map[string]string{
		"non_https":     "http://api.kontext.dev",
		"missing_host":  "https:///path",
		"invalid_port":  "https://api.kontext.dev:bad",
		"port_too_high": "https://api.kontext.dev:99999",
		"userinfo":      "https://user@api.kontext.dev",
		"path":          "https://api.kontext.dev/org-a",
		"query":         "https://api.kontext.dev?token=1",
		"fragment":      "https://api.kontext.dev#frag",
	}
	for name, cloudURL := range tests {
		t.Run(name, func(t *testing.T) {
			input := strings.Replace(validConfigJSON(), "https://api.kontext.dev", cloudURL, 1)
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatalf("Parse() error = nil, want failure")
			}
		})
	}
}

func TestParseAllowsLoopbackHTTPCloudURLOnlyWithExplicitDevOverride(t *testing.T) {
	for _, cloudURL := range []string{"http://127.0.0.1:4000", "http://localhost:4000", "http://[::1]:4000"} {
		t.Run(cloudURL, func(t *testing.T) {
			input := strings.Replace(validConfigJSON(), "https://api.kontext.dev", cloudURL, 1)
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse() error = nil, want loopback http rejected without override")
			}

			t.Setenv(EnvAllowHTTP, "1")
			cfg, err := Parse([]byte(input))
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if cfg.CloudURL != cloudURL {
				t.Fatalf("CloudURL = %q, want %q", cfg.CloudURL, cloudURL)
			}
		})
	}

	remote := strings.Replace(validConfigJSON(), "https://api.kontext.dev", "http://api.kontext.dev", 1)
	if _, err := Parse([]byte(remote)); err == nil {
		t.Fatal("Parse() error = nil, want remote http rejected with override")
	}
}

func TestParseTokenRefAcceptsValidRefs(t *testing.T) {
	tests := map[string]TokenRef{
		"keychain:kontext-managed-install-token": {Source: "keychain", Name: "kontext-managed-install-token"},
		"env:KONTEXT_INSTALL_TOKEN":              {Source: "env", Name: "KONTEXT_INSTALL_TOKEN"},
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			got, err := ParseTokenRef(input)
			if err != nil {
				t.Fatalf("ParseTokenRef() error = %v", err)
			}
			if got != want {
				t.Fatalf("ParseTokenRef() = %+v, want %+v", got, want)
			}
			if got.String() != input {
				t.Fatalf("String() = %q, want %q", got.String(), input)
			}
		})
	}
}

func TestParseTokenRefRejectsInvalidRefs(t *testing.T) {
	tests := []string{
		"raw-token-value",
		"keychain:",
		"file:token",
		"env:KONTEXT INSTALL TOKEN",
		"env:KONTEXT:INSTALL:TOKEN",
		"env:KONTEXT-INSTALL-TOKEN",
		"env:1TOKEN",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseTokenRef(input); err == nil {
				t.Fatalf("ParseTokenRef() error = nil, want failure")
			}
		})
	}
}

func TestResolveInstallTokenFromEnv(t *testing.T) {
	t.Setenv("KONTEXT_INSTALL_TOKEN", " test-install-token ")
	token, err := ResolveInstallToken(context.Background(), TokenRef{
		Source: "env",
		Name:   "KONTEXT_INSTALL_TOKEN",
	})
	if err != nil {
		t.Fatalf("ResolveInstallToken() error = %v", err)
	}
	if token != "test-install-token" {
		t.Fatalf("ResolveInstallToken() = %q", token)
	}
}

func TestResolveInstallTokenRejectsEmptyEnv(t *testing.T) {
	t.Setenv("KONTEXT_INSTALL_TOKEN", " ")
	_, err := ResolveInstallToken(context.Background(), TokenRef{
		Source: "env",
		Name:   "KONTEXT_INSTALL_TOKEN",
	})
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("ResolveInstallToken() error = %v, want empty env error", err)
	}
}

func TestDeploymentVersionReadsAndTrimsMarker(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "deployment-version")
	if err := os.WriteFile(marker, []byte("  0.2.0\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv(EnvDeploymentVersionPath, marker)
	if got := DeploymentVersion(); got != "0.2.0" {
		t.Fatalf("DeploymentVersion() = %q, want %q", got, "0.2.0")
	}
}

func TestDeploymentVersionMissingMarkerReturnsEmpty(t *testing.T) {
	t.Setenv(EnvDeploymentVersionPath, filepath.Join(t.TempDir(), "missing"))
	if got := DeploymentVersion(); got != "" {
		t.Fatalf("DeploymentVersion() = %q, want empty", got)
	}
}

func TestLoadFileReturnsChecksumAndPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(path, []byte(validConfigJSON()), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if loaded.Path != path {
		t.Fatalf("Path = %q, want %q", loaded.Path, path)
	}
	if len(loaded.Checksum) != 64 {
		t.Fatalf("Checksum = %q, want sha256 hex", loaded.Checksum)
	}
}

func validConfigJSON() string {
	return `{
  "version": "managed-install-v1",
  "cloud_url": "https://api.kontext.dev",
  "mode": "observe",
  "agent": "claude",
  "credentials": {
    "install_token_ref": "env:KONTEXT_INSTALL_TOKEN"
  },
  "device": {
    "label": "Engineering Mac"
  }
}`
}

func replacementFor(field string) string {
	switch field {
	case "install_token_ref":
		return `"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"`
	default:
		return `"` + field + `": "` + map[string]string{
			"version":   "managed-install-v1",
			"cloud_url": "https://api.kontext.dev",
			"mode":      "observe",
			"agent":     "claude",
		}[field] + `"`
	}
}

func TestParseModeRemote(t *testing.T) {
	cfg, err := Parse([]byte(strings.Replace(validConfigJSON(), `"mode": "observe"`, `"mode": "remote"`, 1)))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.Mode != ModeRemote {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, ModeRemote)
	}
}
