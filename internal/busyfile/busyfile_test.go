package busyfile

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// replace writes content the way the daemon writes its state files: a
// temporary file in the same folder, renamed over the target.
func replace(path, content string) error {
	temp, err := os.CreateTemp(filepath.Dir(path), ".state-*.tmp")
	if err != nil {
		return err
	}
	if _, err := temp.WriteString(content); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := Rename(temp.Name(), path); err != nil {
		_ = os.Remove(temp.Name())
		return err
	}
	return nil
}

// A file is read while it is replaced over and over. On Windows a rename
// over an open file and an open of a file being replaced are refused for a
// moment each; neither may reach the caller.
func TestReadWhileReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	const content = `{"kind":"auth"}`
	if err := replace(path, content); err != nil {
		t.Fatal(err)
	}
	var stop atomic.Bool
	writeErr := make(chan error, 1)
	go func() {
		for !stop.Load() {
			if err := replace(path, content); err != nil {
				writeErr <- err
				return
			}
		}
		writeErr <- nil
	}()
	reads := 0
	for end := time.Now().Add(500 * time.Millisecond); time.Now().Before(end); reads++ {
		if data, err := ReadFile(path); err != nil || string(data) != content {
			stop.Store(true)
			<-writeErr
			t.Fatalf("read %d while the file was being replaced = %q, %v", reads, data, err)
		}
	}
	stop.Store(true)
	if err := <-writeErr; err != nil {
		t.Fatalf("a replacement failed while the file was being read: %v", err)
	}
}

// A file is removed while a reader has it open for a moment at a time.
func TestRemoveWhileRead(t *testing.T) {
	dir := t.TempDir()
	for round := 0; round < 50; round++ {
		path := filepath.Join(dir, "state.json")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stop atomic.Bool
		done := make(chan struct{})
		go func() {
			defer close(done)
			for !stop.Load() {
				_, _ = os.ReadFile(path)
			}
		}()
		time.Sleep(time.Millisecond)
		err := Remove(path)
		stop.Store(true)
		<-done
		if err != nil {
			t.Fatalf("round %d: remove while the file was being read: %v", round, err)
		}
	}
}

func TestMissingFileIsNotRetried(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	start := time.Now()
	if _, err := ReadFile(path); !os.IsNotExist(err) {
		t.Fatalf("ReadFile(missing) = %v, want not exist", err)
	}
	if err := Remove(path); !os.IsNotExist(err) {
		t.Fatalf("Remove(missing) = %v, want not exist", err)
	}
	if took := time.Since(start); took > 100*time.Millisecond {
		t.Fatalf("a missing file took %v, want no waiting", took)
	}
}
