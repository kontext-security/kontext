//go:build !windows

package tooloutput

import (
	"os"
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

// A session that only partly goes frees what did go: the cap counts what is
// left and deletes no more sessions than that needs.
func TestPruneCapCountsWhatAPartlyFailedDeleteFreed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	d := newSavedDir(t)
	stuck := d.save("stuck", "toolu_1.txt", 300*mib, 3*day)
	locked := filepath.Join(filepath.Dir(stuck), "locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(locked, "inner"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	kept := []string{
		d.save("middle", "toolu_2.txt", 200*mib, 2*day),
		d.save("newest", "toolu_3.txt", 100*mib, day),
	}
	// 600 MiB: the stuck session's output goes, its locked directory stays,
	// and the 300 MiB left fit.
	d.c.Prune()
	if d.exists(stuck) {
		t.Fatal("output kept in the session the cap deletes first")
	}
	for _, path := range kept {
		if !d.exists(path) {
			t.Fatalf("%s deleted though what was left fit the cap", filepath.Base(path))
		}
	}
}
