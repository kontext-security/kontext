package hermetic

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestHomeSetsEveryHomeVariable(t *testing.T) {
	home := Home(t)
	for _, name := range []string{"HOME", "USERPROFILE"} {
		if got := os.Getenv(name); got != home {
			t.Errorf("%s = %q, want %q", name, got, home)
		}
	}
	got, err := os.UserHomeDir()
	if err != nil || got != home {
		t.Fatalf("os.UserHomeDir() = %q, %v; want %q", got, err, home)
	}
}

func TestSocketDirFitsASocketPath(t *testing.T) {
	// Even with a long temp root, the directory must leave room for the
	// longest socket name the tests use.
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), strings.Repeat("x", 80)))
	dir := SocketDir(t)
	if path := filepath.Join(dir, "kontext-managedobserve-shadow-budget.sock"); len(path) > 104 && runtime.GOOS != "windows" {
		t.Fatalf("socket path %q is %d bytes, over the 104-byte limit", path, len(path))
	}
	if strings.HasPrefix(dir, t.TempDir()) {
		t.Fatalf("socket dir %q is under t.TempDir", dir)
	}
}

func TestSymlinksSkipsOrAllows(t *testing.T) {
	Symlinks(t)
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link")); err != nil {
		t.Fatalf("Symlinks did not skip, but os.Symlink failed: %v", err)
	}
}
