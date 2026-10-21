package fsperm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSyncDirFlushesADirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "entry"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SyncDir(dir); err != nil {
		t.Fatalf("SyncDir() error = %v", err)
	}
}

func TestSyncDirReportsAMissingDirectory(t *testing.T) {
	if err := SyncDir(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("SyncDir() error = nil, want an error for a missing directory")
	}
}
