//go:build windows

package managedobserve

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultSocketPathListensUnderLocalAppData(t *testing.T) {
	// A short parent: sun_path holds 108 bytes and t.TempDir names carry the test name.
	local, err := os.MkdirTemp("", "k")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(local) })
	t.Setenv("LOCALAPPDATA", local)
	t.Setenv(envSocketPath, "")
	path := DefaultSocketPath()
	if want := filepath.Join(local, "Kontext", "run", "managed-observe.sock"); path != want {
		t.Fatalf("DefaultSocketPath() = %q, want %q", path, want)
	}
	if !strings.HasPrefix(path, local+string(filepath.Separator)) {
		t.Fatalf("socket %q is outside local app data %q", path, local)
	}
	if err := EnsureSocketDir(path); err != nil {
		t.Fatalf("EnsureSocketDir: %v", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
}

func TestEnsureSocketDirRefusesPathsWindowsCannotBind(t *testing.T) {
	// A profile path long enough to push the socket past sun_path's 108 bytes.
	local := filepath.Join(t.TempDir(), strings.Repeat("x", 60))
	t.Setenv("LOCALAPPDATA", local)
	t.Setenv(envSocketPath, "")
	path := DefaultSocketPath()
	if len(path) <= 107 {
		t.Fatalf("test path %q is %d bytes, want more than 107", path, len(path))
	}
	err := EnsureSocketDir(path)
	if err == nil || !strings.Contains(err.Error(), envSocketPath) {
		t.Fatalf("EnsureSocketDir(%d-byte path) = %v, want an error naming %s", len(path), err, envSocketPath)
	}
	if _, statErr := os.Stat(filepath.Dir(path)); !os.IsNotExist(statErr) {
		t.Fatalf("created %s for a socket that cannot bind", filepath.Dir(path))
	}
}
