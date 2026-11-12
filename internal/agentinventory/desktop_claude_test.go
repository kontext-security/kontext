package agentinventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// Claude Desktop ships Claude Code in its own folder, with no claude command
// on any PATH. The ways the lookup can fail, written down first:
//   - only the Desktop copy is on the Mac, and inventory says not installed;
//   - several versions are kept, and an older one wins (lexical "2.1.9" over
//     "2.1.10"), so the version shown is stale;
//   - the newest folder is an unfinished download with no program in it, and
//     the agent reads as absent although an older copy works;
//   - files beside the version folders (update state) are taken for versions;
//   - Claude's folder is linked into ~/Documents, and reading it prompts the
//     user from the background daemon;
//   - a folder it cannot read makes the agent look absent, and the scan claims
//     a check it did not make.
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
	t.Run("version", func(t *testing.T) {
		// Kontext never runs a user's binaries as root, so root reads no version.
		if os.Geteuid() == 0 {
			t.Skip("root runs no CLI --version")
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
	})
	t.Run("newest folder unreadable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads any folder")
		}
		newest := filepath.Join(root, "2.1.12")
		scriptFixture(t, filepath.Join(newest, "ddd", "claude.app", "Contents", "MacOS", "claude"), `echo "2.1.12 (Claude Code)"`)
		if err := os.Chmod(newest, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(newest, 0o700) })
		// An older working copy still counts.
		if got, _ := findCLI(home, "claude", map[string]bool{}); got != bundled("2.1.10", "bbb") {
			t.Fatalf("found %q", got)
		}
		// With no working copy left, the scan could not check: unknown, not absent.
		for _, version := range []string{"2.1.9", "2.1.10"} {
			if err := os.RemoveAll(filepath.Join(root, version)); err != nil {
				t.Fatal(err)
			}
		}
		if got, err := agentInstalled(home, "claude_code", map[string]bool{}); got != InstalledUnknown || err == nil {
			t.Fatalf("installed = %s, %v", got, err)
		}
	})
	// Claude's folder moved into ~/Documents and linked back: reading it would
	// prompt from the background, so the lookup does not, and says it could
	// not check.
	t.Run("folder linked into a guarded folder", func(t *testing.T) {
		home := t.TempDir()
		moved := filepath.Join(home, "Documents", "claude-code")
		scriptFixture(t, filepath.Join(moved, "2.1.10", "bbb", "claude.app", "Contents", "MacOS", "claude"), `echo "2.1.10 (Claude Code)"`)
		link := filepath.Join(home, "Library", "Application Support", "Claude", "claude-code")
		if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, link); err != nil {
			t.Fatal(err)
		}
		previous := privacyfolder.Enabled
		privacyfolder.Enabled = true
		t.Cleanup(func() { privacyfolder.Enabled = previous })
		got, err := agentInstalled(home, "claude_code", map[string]bool{})
		if got != InstalledUnknown || !errors.Is(err, errPrivacyGuarded) {
			t.Fatalf("installed = %s, %v", got, err)
		}
	})
	// A claude command on a PATH folder still wins: it is what a terminal runs.
	onPath := scriptFixture(t, filepath.Join(home, ".local", "bin", "claude"), `echo "2.2.0 (Claude Code)"`)
	if got, _ := findCLI(home, "claude", map[string]bool{}); got != onPath {
		t.Fatalf("found %q, want %q", got, onPath)
	}
}
