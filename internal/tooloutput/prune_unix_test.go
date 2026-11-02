//go:build !windows

package tooloutput

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Prune opens no file in a session: a named pipe, which any open would hang
// on, is no saved output and goes with its session.
func TestPruneNeverOpensANamedPipe(t *testing.T) {
	d := newSavedDir(t)
	quiet := d.save("quiet", "toolu_old.txt", 4096, 20*day)
	active := d.save("active", "toolu_new.txt", 4096, time.Hour)
	pipes := []string{filepath.Join(filepath.Dir(quiet), "toolu_pipe.txt"), filepath.Join(filepath.Dir(active), "toolu_pipe.txt")}
	for _, pipe := range pipes {
		if err := syscall.Mkfifo(pipe, 0o600); err != nil {
			t.Skipf("named pipes unavailable: %v", err)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.c.Prune()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Prune blocked on a named pipe")
	}
	if d.exists(filepath.Dir(quiet)) {
		t.Fatal("quiet session kept beside a new named pipe")
	}
	for _, path := range []string{active, pipes[1]} {
		if !d.exists(path) {
			t.Fatalf("%s deleted from a session that saved an hour ago", filepath.Base(path))
		}
	}
}
