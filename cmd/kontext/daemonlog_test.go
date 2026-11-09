package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenDaemonLogAppends(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Kontext")
	for _, line := range []string{"first\n", "second\n"} {
		f, err := openDaemonLog(dir)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}
	data, err := os.ReadFile(filepath.Join(dir, "daemon.log"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "first\nsecond\n" {
		t.Fatalf("log = %q", data)
	}
}

// A log past its cap starts over, and the previous one is kept beside it.
func TestOpenDaemonLogRotatesPastItsCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxDaemonLogBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openDaemonLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if info, err := os.Stat(path); err != nil || info.Size() != 0 {
		t.Fatalf("new log: %v, %v", info, err)
	}
	if info, err := os.Stat(path + ".1"); err != nil || info.Size() != maxDaemonLogBytes+1 {
		t.Fatalf("previous log: %v, %v", info, err)
	}
}

// A rotation that fails leaves the log in use and says so in it.
func TestOpenDaemonLogNotesAFailedRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxDaemonLogBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	// A non-empty folder where the previous log goes makes the rename fail.
	if err := os.MkdirAll(filepath.Join(path+".1", "busy"), 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := openDaemonLog(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "\n") || !strings.Contains(string(data), "couldn't be rotated") {
		t.Fatalf("log doesn't note the failed rotation; tail %q", data[len(data)-80:])
	}
}
