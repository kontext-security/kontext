//go:build windows

package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

// The hooks name the socket, so a path Windows cannot bind is refused before any
// hook is written, and the error names both ways to set a shorter one.
func TestRunDaemonRefusesUnbindableSocketBeforeHooks(t *testing.T) {
	home := hermetic.Home(t)
	long := filepath.Join(hermetic.SocketDir(t), strings.Repeat("x", 100), "kontext.sock")
	err := runDaemon(context.Background(), []string{"--socket", long, "--db", filepath.Join(t.TempDir(), "guard.db")}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--socket") || !strings.Contains(err.Error(), "KONTEXT_GUARD_SOCKET") {
		t.Fatalf("runDaemon(%d-byte socket) = %v, want the length error naming --socket and KONTEXT_GUARD_SOCKET", len(long), err)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".claude")); !os.IsNotExist(statErr) {
		t.Fatalf("hooks were written for a socket that cannot bind (%v)", statErr)
	}
}

// The standalone install names the socket too, so it refuses the same path.
func TestHooksInstallRefusesUnbindableSocket(t *testing.T) {
	home := hermetic.Home(t)
	long := filepath.Join(hermetic.SocketDir(t), strings.Repeat("x", 100), "kontext.sock")
	err := runHooks([]string{"install", "claude-code", "--socket", long}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--socket") || !strings.Contains(err.Error(), "KONTEXT_GUARD_SOCKET") {
		t.Fatalf("runHooks(install, %d-byte socket) = %v, want the length error naming --socket and KONTEXT_GUARD_SOCKET", len(long), err)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".claude")); !os.IsNotExist(statErr) {
		t.Fatalf("hooks were written for a socket that cannot bind (%v)", statErr)
	}
}
