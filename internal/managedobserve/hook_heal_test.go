package managedobserve

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/antigravitymanaged"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/managedconfig"
)

// On an organization-managed Mac the daemon writes the hooks of an agent that
// reads no machine-wide file (Antigravity), naming the package's binary, and
// never a user copy of Claude Code, Codex or Cursor hooks: the package's
// machine-wide files run those, and a second set would run every hook twice.
// The inventory then reports the agent wired.
func TestManagedHealerWiresPerUserAgentsOnly(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the daemon heals hooks on macOS only")
	}
	home := t.TempDir()
	hermetic.SetHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	for _, d := range agentinventory.Catalog {
		if d.ConfigEnv != "" {
			t.Setenv(d.ConfigEnv, "")
		}
	}
	// Every agent is present: each has a config file of its own.
	for _, file := range []string{".claude/state.json", ".codex/state.json", ".cursor/mcp.json", ".gemini/antigravity/state.json"} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(home, file)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, file), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	config := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(config, []byte(`{"version":"managed-install-v1","cloud_url":"https://api.kontext.dev","mode":"observe","agent":"claude","credentials":{"install_token_ref":"env:KONTEXT_INSTALL_TOKEN"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managedconfig.EnvPath, config)
	loaded, err := managedconfig.Load()
	if err != nil || loaded.Scope == managedconfig.ScopeUser {
		t.Fatalf("config %+v: %v", loaded, err)
	}
	binary := hermetic.KontextBinary(t, t.TempDir())
	previousBinary, previousExe := managedHookBinary, executablePath
	managedHookBinary, executablePath = binary, func() (string, error) { return binary, nil }
	t.Cleanup(func() { managedHookBinary, executablePath = previousBinary, previousExe })

	heal := hookHealer(loaded, diagnostic.Logger{})
	if heal == nil {
		t.Fatal("an organization-managed config got no hook healer")
	}
	if !heal() {
		t.Fatal("the healer changed nothing")
	}
	raw, err := os.ReadFile(antigravitymanaged.UserHooksPath(home))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := antigravitymanaged.ValidateInstalled(raw); err != nil || got != binary {
		t.Fatalf("Antigravity hooks name %q: %v", got, err)
	}
	for _, path := range []string{".claude/settings.json", ".codex/hooks.json", ".codex/config.toml", ".cursor/hooks.json"} {
		if _, err := os.Lstat(filepath.Join(home, path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the managed daemon wrote %s: %v", path, err)
		}
	}
	if wired := antigravityWired(); wired != agentinventory.WiredYes {
		t.Fatalf("inventory reports Antigravity %q", wired)
	}
	if heal() {
		t.Fatal("a second pass changed a complete file")
	}
	// Another binary (an old process after an upgrade, or a developer build)
	// writes nothing.
	if err := os.Remove(antigravitymanaged.UserHooksPath(home)); err != nil {
		t.Fatal(err)
	}
	executablePath = func() (string, error) { return hermetic.KontextBinary(t, t.TempDir()), nil }
	if heal() {
		t.Fatal("a binary other than the package's wrote hooks")
	}
}

// Every agent Kontext wires has a wiring check in the inventory, or the
// dashboard cannot say whether it is governed.
func TestEveryWiredAgentHasAnInventoryCheck(t *testing.T) {
	wiring := AgentWiring(managedconfig.ScopeSystem)
	for _, scope := range []hookinstall.Scope{hookinstall.User, hookinstall.System} {
		defs, err := hookinstall.Definitions(scope, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		for _, def := range defs {
			if wiring[def.Agent] == nil {
				t.Errorf("%s has hooks but no wiring check: add it to agentWiring in agent_inventory.go", def.Agent)
			}
		}
	}
}
