package localruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSocketDirIsPerUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		local := t.TempDir()
		t.Setenv("LOCALAPPDATA", local)
		if got, want := SocketDir("guard"), filepath.Join(local, "Kontext", "run", "guard"); got != want {
			t.Fatalf("SocketDir() = %q, want %q", got, want)
		}
		return
	}
	if got, want := SocketDir("guard"), filepath.Join("/tmp", fmt.Sprintf("kontext-guard-%d", os.Getuid())); got != want {
		t.Fatalf("SocketDir() = %q, want %q", got, want)
	}
}
