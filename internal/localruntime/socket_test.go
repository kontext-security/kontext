package localruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSocketPathIsPerUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		local := t.TempDir()
		t.Setenv("LOCALAPPDATA", local)
		if got, want := SocketPath("guard"), filepath.Join(local, "Kontext", "run", "guard.sock"); got != want {
			t.Fatalf("SocketPath() = %q, want %q", got, want)
		}
		return
	}
	if got, want := SocketPath("guard"), filepath.Join("/tmp", fmt.Sprintf("kontext-guard-%d", os.Getuid()), "kontext.sock"); got != want {
		t.Fatalf("SocketPath() = %q, want %q", got, want)
	}
}

func TestCheckSocketPathOnlyLimitsWindows(t *testing.T) {
	long := filepath.Join(t.TempDir(), strings.Repeat("x", 120), "guard.sock")
	err := CheckSocketPath(long, "KONTEXT_GUARD_SOCKET")
	if runtime.GOOS == "windows" {
		if err == nil || !strings.Contains(err.Error(), "KONTEXT_GUARD_SOCKET") {
			t.Fatalf("CheckSocketPath(%d bytes) = %v, want an error naming the override", len(long), err)
		}
		return
	}
	if err != nil {
		t.Fatalf("CheckSocketPath off Windows = %v, want nil (the bind reports it)", err)
	}
}
