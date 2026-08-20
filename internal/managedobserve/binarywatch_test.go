package managedobserve

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

func TestBinaryWatchdogFiresWhenFileDeleted(t *testing.T) {
	resetUpdaterSeams(t)
	t.Setenv(envBinaryWatchInterval, "10ms")
	runtimeGOOS = "darwin"
	path := writeWatchdogBinary(t)
	executablePath = func() (string, error) { return path, nil }
	evalSymlinksPath = filepath.EvalSymlinks

	replaced := startBinaryWatchdog(context.Background(), diagnostic.Logger{})
	if err := os.Remove(path); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	assertWatchdogFires(t, replaced)
}

func TestBinaryWatchdogFiresWhenFileReplaced(t *testing.T) {
	resetUpdaterSeams(t)
	t.Setenv(envBinaryWatchInterval, "10ms")
	runtimeGOOS = "darwin"
	path := writeWatchdogBinary(t)
	executablePath = func() (string, error) { return path, nil }
	evalSymlinksPath = filepath.EvalSymlinks

	replaced := startBinaryWatchdog(context.Background(), diagnostic.Logger{})
	// Rename over the original (like a real installer) — remove+rewrite can
	// reuse the inode on some filesystems and defeat os.SameFile.
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte("new"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("Rename() error = %v", err)
	}
	assertWatchdogFires(t, replaced)
}

func TestBinaryWatchdogFiresWhenSymlinkRetargeted(t *testing.T) {
	resetUpdaterSeams(t)
	t.Setenv(envBinaryWatchInterval, "10ms")
	runtimeGOOS = "darwin"
	dir := t.TempDir()
	oldKeg := filepath.Join(dir, "Cellar-old-kontext")
	newKeg := filepath.Join(dir, "Cellar-new-kontext")
	link := filepath.Join(dir, "kontext")
	for _, path := range []string{oldKeg, newKeg} {
		if err := os.WriteFile(path, []byte(path), 0o755); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
	}
	if err := os.Symlink(oldKeg, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	executablePath = func() (string, error) { return link, nil }
	evalSymlinksPath = filepath.EvalSymlinks

	replaced := startBinaryWatchdog(context.Background(), diagnostic.Logger{})
	// brew retargets the bin symlink but keeps the old keg (e.g. under
	// HOMEBREW_NO_INSTALL_CLEANUP) — the watched file itself never changes.
	if err := os.Remove(link); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if err := os.Symlink(newKeg, link); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	assertWatchdogFires(t, replaced)
}

func TestBinaryWatchdogDoesNotFireWhenFileUnchanged(t *testing.T) {
	resetUpdaterSeams(t)
	t.Setenv(envBinaryWatchInterval, "10ms")
	runtimeGOOS = "darwin"
	path := writeWatchdogBinary(t)
	executablePath = func() (string, error) { return path, nil }
	evalSymlinksPath = filepath.EvalSymlinks
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	replaced := startBinaryWatchdog(ctx, diagnostic.Logger{})
	assertWatchdogDoesNotFire(t, replaced)
}

func TestBinaryWatchdogSkipsNonDarwin(t *testing.T) {
	resetUpdaterSeams(t)
	runtimeGOOS = "linux"

	replaced := startBinaryWatchdog(context.Background(), diagnostic.Logger{})
	assertWatchdogClosed(t, replaced)
}

func TestBinaryWatchdogSkipsExecutablePathError(t *testing.T) {
	resetUpdaterSeams(t)
	runtimeGOOS = "darwin"
	executablePath = func() (string, error) { return "", errors.New("missing executable") }

	replaced := startBinaryWatchdog(context.Background(), diagnostic.Logger{})
	assertWatchdogClosed(t, replaced)
}

func TestBinaryWatchdogFiresWhenBinaryDisappearsDuringInitialization(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(string)
	}{
		{
			name: "resolve",
			setup: func(string) {
				evalSymlinksPath = func(string) (string, error) { return "", fs.ErrNotExist }
			},
		},
		{
			name: "stat",
			setup: func(path string) {
				evalSymlinksPath = func(string) (string, error) { return path, nil }
				statPath = func(string) (os.FileInfo, error) { return nil, fs.ErrNotExist }
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetUpdaterSeams(t)
			runtimeGOOS = "darwin"
			path := writeWatchdogBinary(t)
			executablePath = func() (string, error) { return path, nil }
			tc.setup(path)

			replaced := startBinaryWatchdog(context.Background(), diagnostic.Logger{})
			assertWatchdogFires(t, replaced)
		})
	}
}

func TestBinaryWatchdogStopsWhenContextCancelled(t *testing.T) {
	resetUpdaterSeams(t)
	t.Setenv(envBinaryWatchInterval, "10ms")
	runtimeGOOS = "darwin"
	path := writeWatchdogBinary(t)
	executablePath = func() (string, error) { return path, nil }
	evalSymlinksPath = filepath.EvalSymlinks
	ctx, cancel := context.WithCancel(context.Background())

	cfg, err := binaryWatchdogConfig()
	if err != nil {
		t.Fatalf("binaryWatchdogConfig() error = %v", err)
	}
	replaced := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		runBinaryWatchdog(ctx, cfg, diagnostic.Logger{}, replaced)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchdog did not stop after context cancellation")
	}
	select {
	case <-replaced:
		t.Fatal("watchdog fired while stopping")
	default:
	}
}

func writeWatchdogBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kontext")
	if err := os.WriteFile(path, []byte("old"), 0o755); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func assertWatchdogFires(t *testing.T, replaced <-chan struct{}) {
	t.Helper()
	select {
	case _, ok := <-replaced:
		if !ok {
			t.Fatal("watchdog channel closed without firing")
		}
	case <-time.After(time.Second):
		t.Fatal("watchdog did not fire")
	}
}

func assertWatchdogDoesNotFire(t *testing.T, replaced <-chan struct{}) {
	t.Helper()
	select {
	case <-replaced:
		t.Fatal("watchdog fired")
	case <-time.After(30 * time.Millisecond):
	}
}

func assertWatchdogClosed(t *testing.T, replaced <-chan struct{}) {
	t.Helper()
	select {
	case _, ok := <-replaced:
		if ok {
			t.Fatal("watchdog fired")
		}
	case <-time.After(time.Second):
		t.Fatal("watchdog channel did not close")
	}
}
