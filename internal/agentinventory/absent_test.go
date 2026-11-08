package agentinventory

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Ways this can fail, written before the code:
//  1. An agent that is really present is called absent and loses its hooks.
//  2. A check that could not answer counts as absence.
//  3. Kontext's own hook files count as the agent, so nothing is ever skipped.
//  4. An id outside the catalog is called absent.
func TestAbsent(t *testing.T) {
	absent := func(home, id string) bool {
		return Absent(context.Background(), home, noEnv, id)
	}

	t.Run("nothing on disk", func(t *testing.T) {
		// Codex has a command to look for on every platform; Windsurf is only a
		// macOS app, so elsewhere its install state stays unknown.
		if !absent(t.TempDir(), "codex") {
			t.Fatal("empty home must be absent")
		}
	})
	t.Run("own config is present", func(t *testing.T) {
		home := t.TempDir()
		writeHomeFile(t, home, ".windsurf/settings.json", "{}")
		if absent(home, "windsurf") {
			t.Fatal("own config must not be absent")
		}
	})
	t.Run("only kontext hooks is still absent", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("CODEX_HOME", "")
		installAllHooks(t, home)
		for _, id := range []string{"cursor", "codex", "claude_code", "antigravity"} {
			if !absent(home, id) {
				t.Fatalf("%s: Kontext's files must not count as the agent", id)
			}
		}
	})
	t.Run("unreadable is not absent", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads everything")
		}
		// The second config location sits under a folder the scan cannot enter;
		// the app and binary checks in the home stay readable.
		home := t.TempDir()
		dir := filepath.Join(home, ".codeium")
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
		if absent(home, "windsurf") {
			t.Fatal("a check that could not answer must not be absence")
		}
	})
	t.Run("expired deadline is not absent", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if Absent(ctx, t.TempDir(), noEnv, "windsurf") {
			t.Fatal("a scan that did not run must not be absence")
		}
	})
	t.Run("unknown id is not absent", func(t *testing.T) {
		if absent(t.TempDir(), "not_a_catalog_agent") {
			t.Fatal("unknown agents must keep their hooks")
		}
	})
}
