package managedobserve

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDaemonStatusRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	if err := WriteDaemonStatus(dbPath, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	got := LoadDaemonStatus(dbPath)
	if got == nil || got.Version != "1.2.3" || got.PID != os.Getpid() || got.StartedAt == "" {
		t.Fatalf("LoadDaemonStatus = %+v", got)
	}
	if _, err := time.Parse(time.RFC3339, got.StartedAt); err != nil {
		t.Fatalf("StartedAt = %q, want RFC3339: %v", got.StartedAt, err)
	}
}

// The build stamp has to survive the file, not just the struct: doctor reads
// these fields back from a breadcrumb another process wrote. (WriteDaemonStatus
// reads the running binary's own stamp, and a test binary has none, so the
// written values are exercised through JSON here rather than through a stub.)
func TestDaemonStatusRoundTripsBuildStamp(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	const revision = "cac15fd669a7e4b0bfbdd78413d25fc0999e3a11"
	written := `{"version":"1.2.3","revision":"` + revision + `","modified":true,"pid":1,"started_at":"2026-07-31T12:00:00Z"}`
	if err := os.WriteFile(DaemonStatusPath(dbPath), []byte(written), 0o600); err != nil {
		t.Fatal(err)
	}
	got := LoadDaemonStatus(dbPath)
	if got == nil || got.Revision != revision || !got.Modified {
		t.Fatalf("LoadDaemonStatus = %+v, want the revision and modified flag preserved", got)
	}

	// Absent fields must read as "no stamp recorded", which is what every daemon
	// predating them wrote.
	legacy := filepath.Join(t.TempDir(), "guard.db")
	if err := os.WriteFile(DaemonStatusPath(legacy), []byte(`{"version":"1.2.3","pid":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadDaemonStatus(legacy); got == nil || got.Revision != "" || got.Modified {
		t.Fatalf("LoadDaemonStatus legacy = %+v, want no revision and not modified", got)
	}
}

func TestLoadDaemonStatusMissingFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	if got := LoadDaemonStatus(dbPath); got != nil {
		t.Fatalf("LoadDaemonStatus missing = %+v, want nil", got)
	}
}

func TestLoadDaemonStatusCorruptFile(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	if err := os.WriteFile(DaemonStatusPath(dbPath), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := LoadDaemonStatus(dbPath); got != nil {
		t.Fatalf("LoadDaemonStatus corrupt = %+v, want nil", got)
	}
}

func TestDaemonStatusFileMode(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "guard.db")

	if err := WriteDaemonStatus(dbPath, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(DaemonStatusPath(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("daemon status mode = %v, want 0600", got)
	}
}
