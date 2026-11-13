// Package hermetic gives a test a home and a socket directory of its own on
// every OS, so the suite writes nothing outside the temp dirs it creates.
package hermetic

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
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
	setHome(t.Setenv, dir)
}

// MainHome points the home directory at a fresh temp dir for the whole test
// binary, as Home does for one test, and returns the dir. TestMain calls it
// before m.Run and removes the dir after; a test that sets a home of its own
// gets this one back when it ends. An error means the home may be only partly
// set, so TestMain must stop without running the tests.
func MainHome() (string, error) {
	home, err := os.MkdirTemp("", "kontext-home")
	if err != nil {
		return "", err
	}
	var errs []error
	setHome(func(key, value string) { errs = append(errs, os.Setenv(key, value)) }, home)
	if err := errors.Join(errs...); err != nil {
		_ = os.RemoveAll(home)
		return "", err
	}
	return home, nil
}

func setHome(setenv func(key, value string), dir string) {
	setenv("HOME", dir)
	setenv("USERPROFILE", dir)
	if volume := filepath.VolumeName(dir); volume != "" {
		setenv("HOMEDRIVE", volume)
		setenv("HOMEPATH", dir[len(volume):])
	}
	// On Windows a user's state is not under the home variables but under
	// these two, so a test with a home of its own must not reach the real
	// ones.
	if runtime.GOOS == "windows" {
		setenv("LOCALAPPDATA", filepath.Join(dir, "AppData", "Local"))
		setenv("APPDATA", filepath.Join(dir, "AppData", "Roaming"))
	}
}

// StateDir is the Kontext state folder of a user whose home is home, laid out
// as SetHome sets it: Library/Application Support/Kontext under the home, and
// on Windows AppData\Local\Kontext under it.
func StateDir(home string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "AppData", "Local", "Kontext")
	}
	return filepath.Join(home, "Library", "Application Support", "Kontext")
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

// KontextBinary writes a stand-in for the Kontext executable into dir and
// returns its path: kontext with the execute bit, and kontext.exe on Windows,
// where the name is what makes a file one that runs.
func KontextBinary(t testing.TB, dir string) string {
	t.Helper()
	name := "kontext"
	if runtime.GOOS == "windows" {
		name = "kontext.exe"
	}
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("hermetic: kontext binary: %v", err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("hermetic: kontext binary: %v", err)
	}
	return path
}

var issueID = regexp.MustCompile(`^ENG-[0-9]+$`)

// NotOnWindows skips the test on Windows, where what it covers doesn't exist
// yet. issue is the work item that brings it there, so every such skip has an
// owner and can be found again; why says what is missing.
func NotOnWindows(t testing.TB, issue, why string) {
	t.Helper()
	notOn(t, runtime.GOOS, issue, why)
}

func notOn(t testing.TB, goos, issue, why string) {
	t.Helper()
	if !issueID.MatchString(issue) {
		t.Fatalf("hermetic: a Windows skip needs its issue, got %q", issue)
	}
	if goos == "windows" {
		t.Skipf("not on Windows yet (%s): %s", issue, why)
	}
}

// Symlinks skips the test when this user cannot create symlinks, as on
// Windows without Developer Mode or the SeCreateSymbolicLinkPrivilege.
func Symlinks(t testing.TB) {
	t.Helper()
	if err := symlinks(); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}
