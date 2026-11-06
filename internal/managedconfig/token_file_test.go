package managedconfig

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTokenRefAcceptsAFileName(t *testing.T) {
	got, err := ParseTokenRef("file:install-token")
	if err != nil {
		t.Fatal(err)
	}
	if want := (TokenRef{Source: "file", Name: "install-token"}); got != want {
		t.Fatalf("ParseTokenRef() = %+v, want %+v", got, want)
	}
	if got.String() != "file:install-token" {
		t.Fatalf("String() = %q", got.String())
	}
}

// A file ref names a file beside the config, so it can't point anywhere else.
func TestParseTokenRefRejectsFilePaths(t *testing.T) {
	for _, input := range []string{"file:", "file:.", "file:..", "file:../token", "file:dir/token", `file:dir\token`, `file:C:\token`, "file:/etc/token"} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseTokenRef(input); err == nil {
				t.Fatalf("ParseTokenRef(%q) error = nil, want failure", input)
			}
		})
	}
}

func writeTokenConfig(t *testing.T, token string) LoadedConfig {
	t.Helper()
	dir := t.TempDir()
	if token != "" {
		if err := os.WriteFile(filepath.Join(dir, "install-token"), []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return LoadedConfig{
		Path:   filepath.Join(dir, "managed.json"),
		Config: Config{Credentials: Credentials{InstallTokenRef: TokenRef{Source: "file", Name: "install-token"}}},
	}
}

func TestInstallTokenReadsTheFileBesideTheConfig(t *testing.T) {
	loaded := writeTokenConfig(t, " test-install-token\r\n")
	token, err := loaded.InstallToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if token != "test-install-token" {
		t.Fatalf("token = %q", token)
	}
}

func TestInstallTokenRefusesAMissingOrEmptyFile(t *testing.T) {
	if _, err := writeTokenConfig(t, "").InstallToken(context.Background()); err == nil {
		t.Error("a missing token file was accepted")
	}
	if _, err := writeTokenConfig(t, " \n").InstallToken(context.Background()); err == nil {
		t.Error("an empty token file was accepted")
	}
}

func TestInstallTokenRefusesAnOversizedFile(t *testing.T) {
	loaded := writeTokenConfig(t, strings.Repeat("x", maxInstallTokenFileBytes+1))
	if _, err := loaded.InstallToken(context.Background()); err == nil {
		t.Error("an oversized token file was accepted")
	}
}

// A system config's token is held to the same rule as the config itself: on
// Windows only an administrator may have written it.
func TestInstallTokenOfASystemConfigUsesTheSystemRead(t *testing.T) {
	loaded := writeTokenConfig(t, "test-install-token")
	loaded.Scope = ScopeSystem
	previous := readSystemFile
	t.Cleanup(func() { readSystemFile = previous })
	var read string
	readSystemFile = func(path string) ([]byte, error) {
		read = path
		return nil, ErrUntrustedSystemConfig
	}
	if _, err := loaded.InstallToken(context.Background()); !errors.Is(err, ErrUntrustedSystemConfig) {
		t.Fatalf("error = %v, want the system read's refusal", err)
	}
	if want := filepath.Join(filepath.Dir(loaded.Path), "install-token"); read != want {
		t.Fatalf("read %q, want %q", read, want)
	}
}

func TestInstallTokenOfAUserConfigReadsPlainly(t *testing.T) {
	loaded := writeTokenConfig(t, "test-install-token")
	loaded.Scope = ScopeUser
	previous := readSystemFile
	t.Cleanup(func() { readSystemFile = previous })
	readSystemFile = func(string) ([]byte, error) { return nil, ErrUntrustedSystemConfig }
	if token, err := loaded.InstallToken(context.Background()); err != nil || token != "test-install-token" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
}

// Env and keychain refs resolve as they always did.
func TestInstallTokenOfAnEnvRef(t *testing.T) {
	t.Setenv("KONTEXT_INSTALL_TOKEN", "test-install-token")
	loaded := LoadedConfig{Config: Config{Credentials: Credentials{InstallTokenRef: TokenRef{Source: "env", Name: "KONTEXT_INSTALL_TOKEN"}}}}
	if token, err := loaded.InstallToken(context.Background()); err != nil || token != "test-install-token" {
		t.Fatalf("token = %q, err = %v", token, err)
	}
}

// Without the config's folder there's nothing to resolve a file ref against.
func TestResolveInstallTokenRefusesAFileRef(t *testing.T) {
	if _, err := ResolveInstallToken(context.Background(), TokenRef{Source: "file", Name: "install-token"}); err == nil {
		t.Fatal("a file ref resolved without its config")
	}
}
