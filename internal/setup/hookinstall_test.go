package setup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUninstallStopsWhenClaudeManagedRemovalFails(t *testing.T) {
	h := newHarness(t)
	data, err := managedSettingsData("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(managedSettingsPath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedSettingsPath, data, 0644); err != nil {
		t.Fatal(err)
	}
	codexPath := filepath.Join(h.home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(codexPath), 0755); err != nil {
		t.Fatal(err)
	}
	codex := []byte(`{"hooks":{}}`)
	if err := os.WriteFile(codexPath, codex, 0600); err != nil {
		t.Fatal(err)
	}
	denied := errors.New("sudo removal denied")
	overrideVar(t, &geteuid, func() int { return 501 })
	overrideVar(t, &runPrivilegedCommand, func(_ context.Context, name string, args ...string) error {
		if name != "sudo" || len(args) != 3 || args[0] != "rm" || args[2] != managedSettingsPath {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		return denied
	})
	err = Uninstall(context.Background(), Options{Stdout: &h.out, Stderr: &h.errOut})
	if !errors.Is(err, denied) {
		t.Fatalf("Uninstall returned %v, want removal failure", err)
	}
	if strings.Contains(h.out.String(), "hooks removed") || strings.Contains(h.out.String(), "Kept Claude") {
		t.Fatalf("reported success after failure: %s", &h.out)
	}
	got, err := os.ReadFile(codexPath)
	if err != nil || string(got) != string(codex) {
		t.Fatalf("continued with Codex cleanup: %q %v", got, err)
	}
	if _, err := os.Stat(managedSettingsPath); err != nil {
		t.Fatalf("Claude file changed: %v", err)
	}
}
