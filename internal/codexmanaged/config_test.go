package codexmanaged

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func readConfig(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestEnsureHooksEnabledCreatesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	changed, err := EnsureHooksEnabled(path, "kontext-setup")
	if err != nil {
		t.Fatalf("EnsureHooksEnabled() error = %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true for a created file")
	}
	if got := readConfig(t, path); got != "[features]\nhooks = true\n" {
		t.Fatalf("created config = %q", got)
	}
}

func TestHooksEnabledIsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if _, err := HooksEnabled(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("HooksEnabled(missing) error = %v, want not exist", err)
	}
	if err := os.WriteFile(path, []byte("[features]\ncodex_hooks = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enabled, err := HooksEnabled(path)
	if err != nil || !enabled {
		t.Fatalf("HooksEnabled() = (%v, %v), want (true, nil)", enabled, err)
	}
}

func TestEnsureHooksEnabledInsertsIntoExistingFeaturesTable(t *testing.T) {
	path := writeConfig(t, "model = \"gpt-5.5\"\n\n[features]\njs_repl = false\n\n[mcp_servers.node_repl]\nargs = []\n")
	changed, err := EnsureHooksEnabled(path, "kontext-setup")
	if err != nil {
		t.Fatalf("EnsureHooksEnabled() error = %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	got := readConfig(t, path)
	if !strings.Contains(got, "[features]\nhooks = true\njs_repl = false") {
		t.Fatalf("hooks not inserted under [features]: %q", got)
	}
	// Foreign content survives untouched.
	for _, want := range []string{`model = "gpt-5.5"`, "[mcp_servers.node_repl]", "args = []"} {
		if !strings.Contains(got, want) {
			t.Fatalf("foreign content lost (%q): %q", want, got)
		}
	}
}

func TestEnsureHooksEnabledFlipsFalse(t *testing.T) {
	path := writeConfig(t, "[features]\nhooks = false\njs_repl = false\n")
	changed, err := EnsureHooksEnabled(path, "kontext-setup")
	if err != nil {
		t.Fatalf("EnsureHooksEnabled() error = %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true")
	}
	got := readConfig(t, path)
	if strings.Contains(got, "hooks = false") || !strings.Contains(got, "hooks = true") {
		t.Fatalf("hooks not flipped to true: %q", got)
	}
	if !strings.Contains(got, "js_repl = false") {
		t.Fatalf("sibling key lost: %q", got)
	}
}

func TestEnsureHooksEnabledIsIdempotent(t *testing.T) {
	for _, content := range []string{
		"[features]\nhooks = true\n",
		"[features]\ncodex_hooks = true\n",
		"features.hooks = true\n",
	} {
		path := writeConfig(t, content)
		changed, err := EnsureHooksEnabled(path, "kontext-setup")
		if err != nil {
			t.Fatalf("EnsureHooksEnabled(%q) error = %v", content, err)
		}
		if changed {
			t.Fatalf("changed = true for already-enabled config %q", content)
		}
		if got := readConfig(t, path); got != content {
			t.Fatalf("already-enabled config rewritten: %q -> %q", content, got)
		}
	}
}

func TestEnsureHooksEnabledRefusesUneditableFeatures(t *testing.T) {
	for _, content := range []string{
		"features = { js_repl = false }\n",
		"features.js_repl = false\n",
	} {
		path := writeConfig(t, content)
		_, err := EnsureHooksEnabled(path, "kontext-setup")
		if !errors.Is(err, ErrFeaturesNotEditable) {
			t.Fatalf("EnsureHooksEnabled(%q) error = %v, want ErrFeaturesNotEditable", content, err)
		}
		if got := readConfig(t, path); got != content {
			t.Fatalf("uneditable config was modified: %q -> %q", content, got)
		}
	}
}

func TestEnsureHooksEnabledPreservesModeAndBacksUp(t *testing.T) {
	path := writeConfig(t, "[features]\njs_repl = false\n")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureHooksEnabled(path, "kontext-setup"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v, want 0644 preserved", info.Mode().Perm())
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	backups := 0
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "kontext-setup-backup-") {
			backups++
		}
	}
	if backups != 1 {
		t.Fatalf("backups = %d, want 1", backups)
	}
}
