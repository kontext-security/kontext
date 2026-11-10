package hermetic

import (
	"fmt"
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

func TestMainHomeSetsEveryHomeVariable(t *testing.T) {
	// t.Setenv puts back what MainHome sets when the test ends.
	for _, name := range []string{"HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH"} {
		t.Setenv(name, "")
	}
	home, err := MainHome()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
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

// recorder stands in for a test, to see what a helper does to it.
type recorder struct {
	testing.TB
	skipped, failed string
}

func (r *recorder) Helper() {}
func (r *recorder) Skipf(format string, args ...any) {
	r.skipped = fmt.Sprintf(format, args...)
}
func (r *recorder) Fatalf(format string, args ...any) {
	r.failed = fmt.Sprintf(format, args...)
}

func TestNotOnWindowsSkipsThereAndNamesItsIssue(t *testing.T) {
	var onWindows, elsewhere, unowned recorder
	notOn(&onWindows, "windows", "ENG-1", "no launchd")
	notOn(&elsewhere, "linux", "ENG-1", "no launchd")
	notOn(&unowned, "windows", "later", "no launchd")
	if onWindows.skipped != "not on Windows yet (ENG-1): no launchd" || onWindows.failed != "" {
		t.Errorf("on Windows: skipped %q, failed %q", onWindows.skipped, onWindows.failed)
	}
	if elsewhere.skipped != "" || elsewhere.failed != "" {
		t.Errorf("on Linux: skipped %q, failed %q", elsewhere.skipped, elsewhere.failed)
	}
	if unowned.failed == "" {
		t.Error("a skip without an issue was accepted")
	}
}

func TestKontextBinaryIsOneThisOSRuns(t *testing.T) {
	path := KontextBinary(t, filepath.Join(t.TempDir(), "tools"))
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if filepath.Base(path) != "kontext.exe" {
			t.Errorf("name = %s, want kontext.exe", filepath.Base(path))
		}
	} else if filepath.Base(path) != "kontext" || info.Mode().Perm()&0o111 == 0 {
		t.Errorf("%s with mode %v, want kontext with the execute bit", filepath.Base(path), info.Mode().Perm())
	}
}
