package localruntime

import (
	"path/filepath"
	"strings"
	"testing"
)

// A hook started with a filtered environment must look where its daemon
// listens, not in a folder on the current drive.
func TestSocketPathWithoutLocalAppData(t *testing.T) {
	t.Setenv("LOCALAPPDATA", "")
	got := SocketPath("guard")
	if !filepath.IsAbs(got) || !strings.HasSuffix(got, filepath.Join("Kontext", "run", "guard.sock")) {
		t.Fatalf("SocketPath() = %q, want an absolute path under Kontext\\run", got)
	}
}
