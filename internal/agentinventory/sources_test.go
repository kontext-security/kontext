package agentinventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

var sourceTime = time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)

func noEnv(string) string { return "" }

func scanHome(t *testing.T, home string) Inventory {
	t.Helper()
	return Scan(context.Background(), home, noEnv, sourceTime, ScanOptions{})
}

func sourceOf(t *testing.T, inv Inventory, id string) agentauthority.SourceResult {
	t.Helper()
	for _, source := range inv.Sources {
		if source.ID == id {
			return source
		}
	}
	t.Fatalf("no result for %s in %+v", id, inv.Sources)
	return agentauthority.SourceResult{}
}

func rowOf(inv Inventory, id string) *Agent {
	for i := range inv.Agents {
		if inv.Agents[i].ID == id {
			return &inv.Agents[i]
		}
	}
	return nil
}

func listedIDs(inv Inventory) []string {
	ids := []string{}
	for _, agent := range inv.Agents {
		ids = append(ids, agent.ID)
	}
	return ids
}

func writeHomeFile(t *testing.T, home, rel, content string) {
	t.Helper()
	path := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func installAllHooks(t *testing.T, home string) string {
	t.Helper()
	binary := filepath.Join(home, "tools", "kontext")
	writeHomeFile(t, home, "tools/kontext", "#!/bin/sh\n")
	if err := os.Chmod(binary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := hookinstall.Install(hookinstall.Options{Scope: hookinstall.User, Home: home, Binary: binary, ClaudePath: filepath.Join(home, "none", "dropin.json"), CursorPath: filepath.Join(home, "none", "cursor.json"), CodexPath: filepath.Join(home, "none", "codex.json")}); err != nil {
		t.Fatal(err)
	}
	return binary
}

// Failure 17: hook install on a machine without the agent lists nothing, and
// every source says so explicitly.
func TestHookInstallWithoutAgentListsNothing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CODEX_HOME", "")
	binary := installAllHooks(t, home)
	wired := map[string]func() Wired{"cursor": func() Wired { return WiredYes }, "codex": func() Wired { return WiredYes }, "claude_code": func() Wired { return WiredYes }, "antigravity": func() Wired { return WiredYes }}

	inv := Scan(context.Background(), home, noEnv, sourceTime, ScanOptions{Wired: wired})
	if len(inv.Agents) != 0 {
		t.Fatalf("hook files listed agents: %+v", inv.Agents)
	}
	for _, id := range []string{"cursor", "codex", "claude_code", "gemini_cli", "antigravity"} {
		if got := sourceOf(t, inv, id+"/presence"); got.Status != agentauthority.StatusComplete || len(got.Reasons) != 0 {
			t.Fatalf("%s presence = %+v", id, got)
		}
	}

	// Removal leaves folders and backups, which are Kontext's too.
	if err := hookinstall.Remove(hookinstall.Options{Scope: hookinstall.User, Home: home, Binary: binary, ClaudePath: filepath.Join(home, "none", "dropin.json"), CursorPath: filepath.Join(home, "none", "cursor.json"), CodexPath: filepath.Join(home, "none", "codex.json")}); err != nil {
		t.Fatal(err)
	}
	if inv := Scan(context.Background(), home, noEnv, sourceTime, ScanOptions{Wired: wired}); len(inv.Agents) != 0 {
		t.Fatalf("leftovers listed agents: %+v", inv.Agents)
	}
}

func TestAgentOwnedFilesBesideHooksAreConfigured(t *testing.T) {
	for _, tt := range []struct {
		name, id, rel, content string
	}{
		{"cursor mcp", "cursor", ".cursor/mcp.json", `{}`},
		{"cursor projects", "cursor", ".cursor/projects/p1/t.jsonl", "x"},
		{"claude settings key", "claude_code", ".claude/settings.json", `{"model":"opus"}`},
		{"claude agent file", "claude_code", ".claude/CLAUDE.md", "notes"},
		{"codex own config", "codex", ".codex/config.toml", "model = \"gpt\"\n"},
		{"codex own hook", "codex", ".codex/hooks.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"/usr/bin/true"}]}]}}`},
		{"cursor own hook", "cursor", ".cursor/hooks.json", `{"version":1,"hooks":{"stop":[{"command":"/usr/bin/true"}]}}`},
		{"gemini own settings", "gemini_cli", ".gemini/settings.json", `{}`},
		{"antigravity state", "antigravity", ".gemini/antigravity/state.json", `{}`},
		{"antigravity config", "antigravity", ".gemini/config/mcp_config.json", `{}`},
		{"malformed hook file is not ours", "cursor", ".cursor/hooks.json", `{`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("CODEX_HOME", "")
			installAllHooks(t, home)
			writeHomeFile(t, home, tt.rel, tt.content)
			inv := scanHome(t, home)
			row := rowOf(inv, tt.id)
			if row == nil || !row.Configured || row.Installed != InstalledNo {
				t.Fatalf("row = %+v in %v", row, listedIDs(inv))
			}
		})
	}
}

func TestSymlinkInConfigFolderIsAgentOwned(t *testing.T) {
	home := t.TempDir()
	writeHomeFile(t, home, "dotfiles/hooks.json", `{}`)
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "dotfiles/hooks.json"), filepath.Join(home, ".cursor/hooks.json")); err != nil {
		t.Fatal(err)
	}
	if row := rowOf(scanHome(t, home), "cursor"); row == nil || !row.Configured {
		t.Fatalf("row = %+v", row)
	}
}

func TestEmptyFolderIsNotConfigured(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".cursor/empty/nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeHomeFile(t, home, ".cursor/.DS_Store", "x")
	inv := scanHome(t, home)
	if rowOf(inv, "cursor") != nil {
		t.Fatalf("empty folder listed: %+v", inv.Agents)
	}
	if got := sourceOf(t, inv, "cursor/presence"); got.Status != agentauthority.StatusComplete {
		t.Fatalf("presence = %+v", got)
	}
}

func TestGeminiDoesNotCountAntigravityFiles(t *testing.T) {
	home := t.TempDir()
	writeHomeFile(t, home, ".gemini/antigravity-cli/state.json", `{}`)
	writeHomeFile(t, home, ".gemini/config/mcp_config.json", `{}`)
	inv := scanHome(t, home)
	if rowOf(inv, "gemini_cli") != nil || rowOf(inv, "antigravity") == nil {
		t.Fatalf("listed %v", listedIDs(inv))
	}
}

func TestEveryCatalogAgentHasAnExplicitResultWhenAbsent(t *testing.T) {
	inv := scanHome(t, t.TempDir())
	if len(inv.Agents) != 0 || len(inv.Sources) != len(Catalog) {
		t.Fatalf("agents=%v sources=%d", inv.Agents, len(inv.Sources))
	}
	for i, descriptor := range Catalog {
		got := inv.Sources[i]
		if got.ID != descriptor.ID+"/presence" || got.Status != agentauthority.StatusComplete || got.Reasons == nil || len(got.Reasons) != 0 || got.StartedAt == "" || got.FinishedAt == "" {
			t.Fatalf("result = %+v", got)
		}
	}
}

// Cowork ships inside Claude.app, so every Claude Desktop install would list it.
func TestClaudeAppAloneDoesNotListCowork(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("app bundles are macOS-only")
	}
	home := t.TempDir()
	writeHomeFile(t, home, "Applications/Claude.app/Contents/Info.plist", "x")
	if row := rowOf(scanHome(t, home), "claude_cowork"); row != nil {
		t.Fatalf("row = %+v", row)
	}
}

// Installed needs no folder at all: an app that was never launched is listed.
func TestInstalledWithoutConfigIsListed(t *testing.T) {
	t.Run("app", func(t *testing.T) {
		if runtime.GOOS != "darwin" {
			t.Skip("app bundles are macOS-only")
		}
		home := t.TempDir()
		writeHomeFile(t, home, "Applications/Cursor.app/Contents/Info.plist", "x")
		inv := scanHome(t, home)
		row := rowOf(inv, "cursor")
		if row == nil || row.Installed != InstalledYes || row.Configured || row.ConfigPath != "~/.cursor" {
			t.Fatalf("row = %+v", row)
		}
		if got := sourceOf(t, inv, "cursor/presence"); got.Status != agentauthority.StatusComplete {
			t.Fatalf("presence = %+v", got)
		}
	})
	t.Run("cli", func(t *testing.T) {
		home, bin := t.TempDir(), t.TempDir()
		path := filepath.Join(bin, "codex")
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", bin)
		row := rowOf(scanHome(t, home), "codex")
		if row == nil || row.Installed != InstalledYes || row.Configured {
			t.Fatalf("row = %+v", row)
		}
	})
}

func TestInstalledUnknownWithoutLookupDoesNotList(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".hermes"), 0o700); err != nil {
		t.Fatal(err)
	}
	inv := scanHome(t, home)
	if rowOf(inv, "hermes") != nil {
		t.Fatalf("unknown install and an empty folder listed: %+v", inv.Agents)
	}
	writeHomeFile(t, home, ".hermes/config.yaml", "x: 1\n")
	row := rowOf(scanHome(t, home), "hermes")
	if row == nil || row.Installed != InstalledUnknown || !row.Configured {
		t.Fatalf("row = %+v", row)
	}
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("needs enforced file modes")
	}
}

// Failure 15: an unreadable folder never reads as an empty complete.
func TestPermissionDeniedIsNeverComplete(t *testing.T) {
	skipIfRoot(t)
	home := t.TempDir()
	dir := filepath.Join(home, ".cursor")
	if err := os.Mkdir(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	inv := scanHome(t, home)
	got := sourceOf(t, inv, "cursor/presence")
	if got.Status == agentauthority.StatusComplete || !slices.Contains(got.Reasons, agentauthority.ReasonPermissionDenied) {
		t.Fatalf("presence = %+v", got)
	}
	if rowOf(inv, "cursor") != nil {
		t.Fatalf("unreadable folder is not evidence: %+v", inv.Agents)
	}
}

func TestUnreadableHookFileIsNeverComplete(t *testing.T) {
	skipIfRoot(t)
	home := t.TempDir()
	writeHomeFile(t, home, ".cursor/hooks.json", `{}`)
	path := filepath.Join(home, ".cursor/hooks.json")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	if got := sourceOf(t, scanHome(t, home), "cursor/presence"); got.Status == agentauthority.StatusComplete || !slices.Contains(got.Reasons, agentauthority.ReasonPermissionDenied) {
		t.Fatalf("presence = %+v", got)
	}
}

func TestPrivacyGuardedConfigIsNeverComplete(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("privacy folders are macOS-only")
	}
	home := t.TempDir()
	env := func(key string) string {
		if key == "CODEX_HOME" {
			return filepath.Join(home, "Documents", "codex")
		}
		return ""
	}
	writeHomeFile(t, home, "Documents/codex/config.toml", "model = \"gpt\"\n")
	inv := Scan(context.Background(), home, env, sourceTime, ScanOptions{})
	if got := sourceOf(t, inv, "codex/presence"); got.Status == agentauthority.StatusComplete || !slices.Contains(got.Reasons, agentauthority.ReasonPermissionDenied) {
		t.Fatalf("presence = %+v", got)
	}
}

// Failure 15: a source the deadline reaches first is failed, not left empty.
func TestDeadlineBeforeSourceIsFailed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	inv := Scan(ctx, t.TempDir(), noEnv, sourceTime, ScanOptions{})
	if !inv.Incomplete || len(inv.Sources) != len(Catalog) {
		t.Fatalf("incomplete=%t sources=%d", inv.Incomplete, len(inv.Sources))
	}
	for _, got := range inv.Sources {
		if got.Status != agentauthority.StatusFailed || !slices.Equal(got.Reasons, []string{agentauthority.ReasonDeadline}) {
			t.Fatalf("result = %+v", got)
		}
	}
}

func TestWalkLimitIsPartial(t *testing.T) {
	home := t.TempDir()
	for i := 0; i <= configWalkLimit; i++ {
		if err := os.MkdirAll(filepath.Join(home, ".cursor", fmt.Sprintf("%05d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got := sourceOf(t, scanHome(t, home), "cursor/presence")
	if got.Status != agentauthority.StatusPartial || !slices.Equal(got.Reasons, []string{agentauthority.ReasonWalkLimit}) {
		t.Fatalf("presence = %+v", got)
	}
}

// Failure 18: version and activity lookups are enrichment.
func TestEnrichmentFailureLeavesSourceComplete(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("app bundles are macOS-only")
	}
	home := t.TempDir()
	writeHomeFile(t, home, "Applications/Cursor.app/Contents/Info.plist", "not a plist")
	writeHomeFile(t, home, ".cursor/mcp.json", `{}`)
	inv := scanHome(t, home)
	AddVersions(context.Background(), home, &inv)
	row := rowOf(inv, "cursor")
	if row == nil || row.Version != nil {
		t.Fatalf("row = %+v", row)
	}
	if got := sourceOf(t, inv, "cursor/presence"); got.Status != agentauthority.StatusComplete || len(got.Reasons) != 0 {
		t.Fatalf("presence = %+v", got)
	}
}

func TestReasonsNeverCarryPaths(t *testing.T) {
	skipIfRoot(t)
	home := t.TempDir()
	dir := filepath.Join(home, ".cursor")
	if err := os.Mkdir(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	data, err := json.Marshal(sourceOf(t, scanHome(t, home), "cursor/presence"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), home) || strings.Contains(string(data), ".cursor") {
		t.Fatalf("path leaked: %s", data)
	}
}
