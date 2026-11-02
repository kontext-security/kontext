package codexmanaged

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func withSystemHooks(t *testing.T, path string, read func(string) ([]byte, error)) {
	t.Helper()
	previousPath, previousRead := SystemHooksPath, readSystemHooks
	SystemHooksPath, readSystemHooks = path, read
	t.Cleanup(func() { SystemHooksPath, readSystemHooks = previousPath, previousRead })
}

// A refused System layer doesn't count, and the user's own layer still does.
func TestInspectInstallationChecksOnlyTheSystemFile(t *testing.T) {
	valid, err := TemplateJSON("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	system, user := filepath.Join(dir, "system.json"), filepath.Join(dir, "user.json")
	for _, path := range []string{system, user} {
		if err := os.WriteFile(path, valid, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	refused := errors.New("refused")
	var checked []string
	withSystemHooks(t, system, func(path string) ([]byte, error) {
		checked = append(checked, path)
		return nil, refused
	})
	got, err := InspectInstallation(InstallationPaths{SystemHooks: system, UserHooks: user})
	if !errors.Is(err, refused) {
		t.Fatalf("InspectInstallation() error = %v, want %v", err, refused)
	}
	if !slices.Equal(checked, []string{system}) {
		t.Fatalf("checked %q, want only %q", checked, system)
	}
	if len(got.Layers) != 1 || got.Layers[0].Path != user {
		t.Fatalf("layers = %+v, want only %s", got.Layers, user)
	}
}

// A folder without the file is no layer, whoever created it.
func TestInspectInstallationWithoutASystemFile(t *testing.T) {
	system := filepath.Join(t.TempDir(), "hooks.json")
	withSystemHooks(t, system, func(string) ([]byte, error) {
		t.Error("checked a file that doesn't exist")
		return nil, nil
	})
	got, err := InspectInstallation(InstallationPaths{SystemHooks: system})
	if !errors.Is(err, ErrIncompleteInstallation) {
		t.Fatalf("InspectInstallation() error = %v, want %v", err, ErrIncompleteInstallation)
	}
	if len(got.Layers) != 0 {
		t.Fatalf("layers = %+v, want none", got.Layers)
	}
}
