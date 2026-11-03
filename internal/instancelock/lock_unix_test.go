//go:build !windows

package instancelock

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAcquireRefusesAPathThatIsNoFile(t *testing.T) {
	path := lockPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if lock, err := Acquire(path, 0); err == nil {
		lock.Release()
		t.Error("took a lock on a FIFO")
	}
}
