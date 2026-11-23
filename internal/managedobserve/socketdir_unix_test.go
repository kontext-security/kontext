//go:build !windows

package managedobserve

import (
	"os"
	"path/filepath"
	"testing"
)

// A socket left in a folder others could write to is removed when the folder
// is made private: another account may have put it there.
func TestRepairingTheSocketFolderRemovesItsSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "ko")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "k.sock")
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSocketDir(socketPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket still there: %v", err)
	}
	// A private folder keeps its socket.
	if err := os.WriteFile(socketPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureSocketDir(socketPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(socketPath); err != nil {
		t.Fatalf("socket of a private folder removed: %v", err)
	}
}
