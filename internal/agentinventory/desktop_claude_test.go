package agentinventory

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// Claude Desktop ships Claude Code in its own folder, with no claude command
// on any PATH. The ways the lookup can fail, written down first:
//   - only the Desktop copy is on the Mac, and inventory says not installed;
//   - several versions are kept, and an older one wins (lexical "2.1.9" over
//     "2.1.10"), so the version shown is stale;
//   - the newest folder is an unfinished download with no program in it, and
//     the agent reads as absent although an older copy works;
//   - files beside the version folders (update state) are taken for versions.
func TestDesktopBundledClaudeCode(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Claude Desktop bundles Claude Code on macOS")
	}
	home := t.TempDir()
	t.Setenv("PATH", t.TempDir())
	root := filepath.Join(home, "Library", "Application Support", "Claude", "claude-code")
	if got, err := agentInstalled(home, "claude_code", map[string]bool{}); got != InstalledNo || err != nil {
		t.Fatalf("empty home: installed = %s, %v", got, err)
	}
	bundled := func(version, build string) string {
		return filepath.Join(root, version, build, "claude.app", "Contents", "MacOS", "claude")
	}
	scriptFixture(t, bundled("2.1.9", "aaa"), `echo "2.1.9 (Claude Code)"`)
	scriptFixture(t, bundled("2.1.10", "bbb"), `echo "2.1.10 (Claude Code)"`)
	// An unfinished download: the folder exists, the program not yet.
	if err := os.MkdirAll(filepath.Join(root, "2.1.11", "ccc", "claude.app", "Contents", "MacOS"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "auto-update-state.json"), []byte(`{"highWaterMark":"9.9.9"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if got, err := agentInstalled(home, "claude_code", map[string]bool{}); got != InstalledYes || err != nil {
		t.Fatalf("installed = %s, %v", got, err)
	}
	if got, _ := findCLI(home, "claude", map[string]bool{}); got != bundled("2.1.10", "bbb") {
		t.Fatalf("found %q, want the newest complete version", got)
	}
	ctx := context.Background()
	deadline := time.Now().Add(10 * time.Second)
	version := ""
	for version == "" && time.Now().Before(deadline) {
		version = agentVersion(ctx, home, "claude_code")
		time.Sleep(20 * time.Millisecond)
	}
	if version != "2.1.10" {
		t.Fatalf("version = %q", version)
	}
	// A claude command on a PATH folder still wins: it is what a terminal runs.
	onPath := scriptFixture(t, filepath.Join(home, ".local", "bin", "claude"), `echo "2.2.0 (Claude Code)"`)
	if got, _ := findCLI(home, "claude", map[string]bool{}); got != onPath {
		t.Fatalf("found %q, want %q", got, onPath)
	}
}
