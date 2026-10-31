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
	if want := runtime.GOOS == "darwin"; Enabled != want {
		t.Fatalf("Enabled = %v on %s, want %v", Enabled, runtime.GOOS, want)
	}
	enabled := Enabled
	Enabled = false
	t.Cleanup(func() { Enabled = enabled })
	home := t.TempDir()
	if Guarded(home, filepath.Join(home, "Documents", "x")) {
		t.Error("Guarded() off macOS")
	}
}

// A folder holding a guarded one is reached by any recursive read from it.
func TestEncloses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the macOS privacy-folder guard does not read Windows paths")
	}
	enabled := Enabled
	Enabled = true
	t.Cleanup(func() { Enabled = enabled })
	home := t.TempDir()
	for path, want := range map[string]bool{
		"/":                                      true,
		home:                                     true,
		filepath.Join(home, "Library"):           true,
		"/Volumes":                               true,
		filepath.Join(home, "Documents"):         false, // guarded itself: Guarded's case
		filepath.Join(home, "code"):              false,
		filepath.Join(home, "Library", "Caches"): false,
		"relative":                               false,
	} {
		if got := Encloses(home, path); got != want {
			t.Errorf("Encloses(%q) = %v, want %v", path, got, want)
		}
	}
	Enabled = false
	if Encloses(home, "/") {
		t.Error("Encloses reported a folder with the guard off")
	}
}

// A wildcard counts as guarded when anything it may match would.
func TestGuardedPattern(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the macOS privacy-folder guard does not read Windows paths")
	}
	enabled := Enabled
	Enabled = true
	t.Cleanup(func() { Enabled = enabled })
	home := t.TempDir()
	for pattern, want := range map[string]bool{
		filepath.Join(home, "Doc*"):               true,
		filepath.Join(home, "D*"):                 true,
		filepath.Join(home, "down?oads"):          true, // APFS is case-insensitive
		filepath.Join(home, "Lib*"):               true, // holds Mobile Documents
		filepath.Join(home, "*", "notes.txt"):     true, // a wildcard above the last element
		filepath.Join(home, "Documents", "*.txt"): true,
		"/Vol*":                             true,
		"/Volumes/*":                        true,
		filepath.Join(home, "code", "*.go"): false,
		filepath.Join(home, "Pictures*"):    false,
		filepath.Join(home, "Library", "Caches", "*"): false,
	} {
		if got := GuardedPattern(home, pattern); got != want {
			t.Errorf("GuardedPattern(%q) = %v, want %v", pattern, got, want)
		}
	}
}

// A link to a folder holding a guarded one holds it too, and a wildcard is
// checked against what it matches.
func TestLinksToEnclosingFolders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the macOS privacy-folder guard does not read Windows paths")
	}
	enabled := Enabled
	Enabled = true
	t.Cleanup(func() { Enabled = enabled })
	hermetic.Symlinks(t)
	root := t.TempDir()
	home := filepath.Join(root, "home")
	code := filepath.Join(home, "code")
	for _, dir := range []string{filepath.Join(home, "Documents"), code} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, path string) string {
		t.Helper()
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		return path
	}
	homeLink := link(home, filepath.Join(root, "home-link"))
	codeLink := link(code, filepath.Join(root, "code-link"))
	link(filepath.Join(home, "Documents"), filepath.Join(code, "docs"))

	if !Encloses(home, homeLink) {
		t.Error("a link to the home folder was not seen to hold its guarded folders")
	}
	if Encloses(home, codeLink) {
		t.Error("a link to a plain folder was reported")
	}
	if !GuardedPattern(home, filepath.Join(homeLink, "Doc*")) {
		t.Error("a wildcard through a link to the home folder was not caught")
	}
	if !GuardedPattern(home, filepath.Join(code, "d*")) {
		t.Error("a wildcard matching a link into Documents was not caught")
	}
	if GuardedPattern(home, filepath.Join(code, "*.go")) {
		t.Error("a plain wildcard was reported")
	}
}
