package managedconfig

import (
	"context"
	"errors"
	"testing"
)

func TestParseTokenRefAcceptsARegistryValueName(t *testing.T) {
	got, err := ParseTokenRef("registry:InstallToken")
	if err != nil {
		t.Fatal(err)
	}
	if want := (TokenRef{Source: "registry", Name: "InstallToken"}); got != want {
		t.Fatalf("ParseTokenRef() = %+v, want %+v", got, want)
	}
}

// The ref names a value under Kontext's policy key, not a key of its own.
func TestParseTokenRefRejectsARegistryPath(t *testing.T) {
	for _, input := range []string{"registry:", `registry:Software\Kontext`, "registry:a/b"} {
		if _, err := ParseTokenRef(input); err == nil {
			t.Errorf("ParseTokenRef(%q) error = nil, want failure", input)
		}
	}
}

func stubRegistry(t *testing.T, read func(key, name string) (string, error)) {
	t.Helper()
	previous := readRegistryString
	t.Cleanup(func() { readRegistryString = previous })
	readRegistryString = read
}

func TestInstallTokenFromTheRegistry(t *testing.T) {
	var gotKey, gotName string
	stubRegistry(t, func(key, name string) (string, error) {
		gotKey, gotName = key, name
		return " test-install-token \r\n", nil
	})
	token, err := ResolveInstallToken(context.Background(), TokenRef{Source: "registry", Name: "InstallToken"})
	if err != nil {
		t.Fatal(err)
	}
	if token != "test-install-token" {
		t.Fatalf("token = %q", token)
	}
	if gotKey != `SOFTWARE\Policies\Kontext` || gotName != "InstallToken" {
		t.Fatalf("read %s value %s", gotKey, gotName)
	}
}

func TestInstallTokenFromTheRegistryRefusesAnEmptyValue(t *testing.T) {
	stubRegistry(t, func(string, string) (string, error) { return " ", nil })
	if _, err := ResolveInstallToken(context.Background(), TokenRef{Source: "registry", Name: "InstallToken"}); err == nil {
		t.Fatal("an empty registry value was accepted")
	}
}

func TestInstallTokenFromTheRegistryKeepsTheReadError(t *testing.T) {
	stubRegistry(t, func(string, string) (string, error) { return "", ErrUntrustedSystemConfig })
	if _, err := ResolveInstallToken(context.Background(), TokenRef{Source: "registry", Name: "InstallToken"}); !errors.Is(err, ErrUntrustedSystemConfig) {
		t.Fatalf("error = %v, want %v", err, ErrUntrustedSystemConfig)
	}
}
