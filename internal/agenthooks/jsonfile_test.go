package agenthooks

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

func TestReadWriteJSONFilePreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")

	if err := WriteJSONFile(path, map[string]any{"a": float64(1)}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode = %v, want 0600", info.Mode().Perm())
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSONFile(path, map[string]any{"a": float64(2)}); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("rewritten file mode = %v, want 0644 preserved", info.Mode().Perm())
	}

	got, err := ReadJSONFile(path, "test hooks")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{"a": float64(2)}) {
		t.Fatalf("round trip = %v", got)
	}
}

func TestWriteJSONFilePreservesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target-hooks.json")
	firstLink := filepath.Join(dir, "first-hooks.json")
	link := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(target, []byte(`{"a":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	hermetic.Symlinks(t)
	if err := os.Symlink(target, firstLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(firstLink, link); err != nil {
		t.Fatal(err)
	}

	if err := WriteJSONFile(link, map[string]any{"a": float64(2)}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("hooks path is no longer a symlink: mode=%v", info.Mode())
	}
	firstInfo, err := os.Lstat(firstLink)
	if err != nil {
		t.Fatal(err)
	}
	if firstInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("intermediate hooks path is no longer a symlink: mode=%v", firstInfo.Mode())
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"a": 2`) {
		t.Fatalf("target content = %s, want rewritten target", data)
	}
}

func TestBackupFilePreservesModeAndContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := BackupFile(path, "kontext-setup"); err != nil {
		t.Fatal(err)
	}
	if err := BackupFile(path, "kontext-setup"); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backups := 0
	for _, entry := range entries {
		if !strings.Contains(entry.Name(), "kontext-setup-backup-") {
			continue
		}
		backups++
		backupPath := filepath.Join(dir, entry.Name())
		info, err := os.Stat(backupPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("backup mode = %v, want original 0640", info.Mode().Perm())
		}
		data, err := os.ReadFile(backupPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != `{"a":1}` {
			t.Fatalf("backup content = %s", data)
		}
	}
	if backups != 2 {
		t.Fatalf("backup count = %d, want 2", backups)
	}

	if err := BackupFile(filepath.Join(dir, "absent.json"), "x"); err != nil {
		t.Fatal(err)
	}
}
