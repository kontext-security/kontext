package privacyfolder

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

// Every way a path can land in a guarded folder, and the near misses that
// must stay readable. Links are resolved by reading them, never their target.
func TestGuarded(t *testing.T) {
	if runtime.GOOS == "windows" {
		// The guard is macOS's and reads paths as /-separated; Linux runs
		// these cases too, but Windows paths do not fit them.
		t.Skip("the macOS privacy-folder guard does not read Windows paths")
	}
	enabled := Enabled
	Enabled = true
	t.Cleanup(func() { Enabled = enabled })
	home := t.TempDir()
	documents := filepath.Join(home, "Documents", "codex")
	dotfiles := filepath.Join(home, "dotfiles")
	for _, dir := range []string{documents, dotfiles} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, name string) string {
		t.Helper()
		path := filepath.Join(home, name)
		hermetic.Symlinks(t)
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	codexHome := link(documents, ".codex")                     // a folder linked into Documents
	userConfig := link("dotfiles/claude.json", ".claude.json") // a dotfile linked elsewhere
	loop := link(".loop", ".loop")                             // a link to itself
	icloud := link(filepath.Join(home, "Library/Mobile Documents/x"), "icloud")

	for _, tc := range []struct {
		path string
		want bool
	}{
		{filepath.Join(home, "Documents", "app", ".mcp.json"), true},
		{filepath.Join(home, "documents", "app"), true}, // APFS is case-insensitive
		{filepath.Join(home, "Desktop"), true},
		{filepath.Join(home, "Downloads", "x"), true},
		{filepath.Join(home, "Library/CloudStorage/Dropbox/x"), true},
		{filepath.Join("/System/Volumes/Data", home, "Documents", "x"), true}, // the data volume firmlink
		{"/Volumes/USB/app/.mcp.json", true},
		{filepath.Join(codexHome, "config.toml"), true},
		{icloud, true},
		{loop, true},
		{filepath.Join(home, "Documentsx", "app"), false},
		{filepath.Join(home, "code", "app", ".mcp.json"), false},
		{userConfig, false},
		{"relative/Documents", false},
	} {
		if got := Guarded(home, tc.path); got != tc.want {
			t.Errorf("Guarded(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}

	// A home on an external volume keeps its own files readable, not other
	// volumes.
	if Guarded("/Volumes/HomeDisk/alice", "/Volumes/HomeDisk/alice/code/.mcp.json") {
		t.Error("Guarded() refused the home's own volume")
	}
	if !Guarded("/Volumes/HomeDisk/alice", "/Volumes/USB/app/.mcp.json") {
		t.Error("Guarded() allowed another volume next to an external home")
	}
}

func TestGuardedOffMacOS(t *testing.T) {
	enabled := Enabled
	Enabled = false
	t.Cleanup(func() { Enabled = enabled })
	home := t.TempDir()
	if Guarded(home, filepath.Join(home, "Documents", "x")) {
		t.Error("Guarded() off macOS")
	}
}
