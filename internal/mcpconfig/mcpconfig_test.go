package mcpconfig

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A FIFO planted as a project's .mcp.json must not stall the hook.
func TestServerURLSkipsNonRegularFiles(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "app")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(project, ".mcp.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Resolver{Home: home, Managed: filepath.Join(home, "managed-mcp.json")}
	if got, _, _ := r.Server("claude", "s", project, "mcp__work__search"); got != "" {
		t.Fatalf("ServerURL() = %q", got)
	}
	if _, err := readFile(filepath.Join(project, ".mcp.json")); err == nil {
		t.Fatal("readFile read a FIFO")
	}
}
