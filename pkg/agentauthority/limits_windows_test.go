//go:build windows

package agentauthority

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestReadGuardedFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	// stat is answered by guardedInfo in access, not by readGuarded.
	for _, mode := range []string{"read", "list", "tail", "cursor"} {
		result := readGuarded(context.Background(), path, mode)
		if !errors.Is(result.err, os.ErrPermission) || result.opened || result.data != nil || result.entries != nil || result.parsed != nil {
			t.Errorf("%s: got %+v, want a refused read", mode, result)
		}
	}
	if isEvictedErr(os.ErrPermission) {
		t.Error("isEvictedErr reported an ordinary refusal as an eviction")
	}
}

func TestGuardedInfoStartsAtTheVolume(t *testing.T) {
	dir, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want []string
	}{
		{`C:\Users\a\.ssh\id`, []string{`C:\Users`, `C:\Users\a`, `C:\Users\a\.ssh`, `C:\Users\a\.ssh\id`}},
		{`\\server\share\home\a\.ssh\id`, []string{`\\server\share\home`, `\\server\share\home\a`, `\\server\share\home\a\.ssh`, `\\server\share\home\a\.ssh\id`}},
	} {
		var walked []string
		stat := func(p string) (os.FileInfo, error) {
			walked = append(walked, p)
			return dir, nil
		}
		if _, err := guardedInfo(tc.path, stat, false); err != nil {
			t.Errorf("%s: %v", tc.path, err)
		}
		if !slices.Equal(walked, tc.want) {
			t.Errorf("%s: walked %q, want %q", tc.path, walked, tc.want)
		}
	}
}

func TestStatRefusesJunctionAndPlaceholderAncestors(t *testing.T) {
	home := t.TempDir()
	ssh := filepath.Join(home, ".ssh")
	key := filepath.Join(ssh, "id_ed25519.pub")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	stat := func(lstat func(string) (os.FileInfo, error)) fileResult {
		r := Report{}
		g := guard{ctx: context.Background(), home: home, roots: allowedRoots(home, managedRoot), report: &r, lstat: lstat}
		return g.access(key, "stat")
	}
	if result := stat(nil); result.err != nil || result.info == nil || !result.info.Mode().IsRegular() {
		t.Fatalf("plain file: %+v", result)
	}
	// A placeholder directory keeps the directory bit; the walk refuses it before the file.
	placeholder := func(p string) (os.FileInfo, error) {
		info, err := os.Lstat(p)
		if p == ssh && err == nil {
			return attributeInfo{info, syscall.Win32FileAttributeData{FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_RECALL_ON_OPEN}}, nil
		}
		return info, err
	}
	if result := stat(placeholder); !errors.Is(result.err, os.ErrPermission) {
		t.Errorf("placeholder ancestor: err = %v, want a refusal", result.err)
	}
	// Go reports a junction as irregular, neither a symlink nor a directory.
	target := filepath.Join(home, "target")
	if err := os.Rename(ssh, target); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", ssh, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if result := stat(nil); !errors.Is(result.err, os.ErrPermission) {
		t.Errorf("junction ancestor: err = %v, want a refusal", result.err)
	}
}
