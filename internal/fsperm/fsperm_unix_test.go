//go:build unix

package fsperm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRestrictFileSetsOwnerOnlyMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Chmod(0o644); err != nil {
		t.Fatal(err)
	}
	if err := RestrictFile(file); err != nil {
		t.Fatalf("RestrictFile() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if private, err := PrivateFile(path, info); err != nil || !private || info.Mode().Perm() != 0o600 {
		t.Fatalf("after RestrictFile: mode %o, PrivateFile %v, %v; want 0600, true", info.Mode().Perm(), private, err)
	}
}

func TestPrivateFileRefusesModesBeyondOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o644, 0o660, 0o400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if private, _ := PrivateFile(path, info); private {
			t.Fatalf("PrivateFile() = true for mode %o, want false", mode)
		}
	}
}
