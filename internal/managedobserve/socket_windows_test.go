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
	if want := filepath.Join(local, "Kontext", "run", "managed-observe", "kontext.sock"); path != want {
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
