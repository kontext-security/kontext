// Package hermetic gives a test a home and a socket directory of its own on
// every OS, so the suite writes nothing outside the temp dirs it creates.
package hermetic

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
)

// Home points the home directory at a fresh temp dir and returns it.
func Home(t testing.TB) string {
	t.Helper()
	home := t.TempDir()
	SetHome(t, home)
	return home
}

// SetHome points the home directory at dir for the rest of the test. On
// Windows os.UserHomeDir reads USERPROFILE, not HOME, and some tools build the
// profile from HOMEDRIVE and HOMEPATH, so all of them are set.
func SetHome(t testing.TB, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	if volume := filepath.VolumeName(dir); volume != "" {
		t.Setenv("HOMEDRIVE", volume)
		t.Setenv("HOMEPATH", dir[len(volume):])
	}
}

// SocketDir returns a fresh directory short enough for a Unix socket path,
// which macOS limits to 104 bytes and Linux to 108. t.TempDir and $TMPDIR can
// be too long (on macOS they lie under /var/folders), so on Unix the directory
// is made under /tmp; Windows has no /tmp, and its per-user %TEMP% is used.
// The directory is removed when the test ends.
func SocketDir(t testing.TB) string {
	t.Helper()
	parent := "/tmp"
	if runtime.GOOS == "windows" {
		parent = ""
	}
	dir, err := os.MkdirTemp(parent, "k")
	if err != nil {
		t.Fatalf("hermetic: socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

var symlinks = sync.OnceValue(func() error {
	dir, err := os.MkdirTemp("", "k")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	return os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link"))
})

// Symlinks skips the test when this user cannot create symlinks, as on
// Windows without Developer Mode or the SeCreateSymbolicLinkPrivilege.
func Symlinks(t testing.TB) {
	t.Helper()
	if err := symlinks(); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}
