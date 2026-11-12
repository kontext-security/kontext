package managedobserve

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/antigravitymanaged"
	"github.com/kontext-security/kontext/internal/claudemanaged"
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

	dropIn := filepath.Join(t.TempDir(), "20-kontext.json")
	swapManagedSettingsPaths(t, dropIn, filepath.Join(filepath.Dir(dropIn), "managed-settings.json"))
	template, err := claudemanaged.TemplateJSON(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, template, 0o644); err != nil {
		t.Fatal(err)
	}

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
	// Package removal deletes the machine-wide hooks first; from then on the
	// daemon, still running until the remover stops it, removes the user's
	// hooks and keeps another tool's entry. A drop-in naming another binary is
	// unclear, and the daemon then changes nothing.
	hooks := antigravitymanaged.UserHooksPath(home)
	withForeign := strings.Replace(string(raw), "{", `{"other-tool":{"Stop":[{"type":"command","command":"/usr/bin/true"}]},`, 1)
	if err := os.WriteFile(hooks, []byte(withForeign), 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := claudemanaged.TemplateJSON(hermetic.KontextBinary(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, other, 0o644); err != nil {
		t.Fatal(err)
	}
	if heal() {
		t.Fatal("the daemon changed hooks while the package's hooks name another binary")
	}
	if err := os.Remove(dropIn); err != nil {
		t.Fatal(err)
	}
	if !heal() {
		t.Fatal("the daemon left its hook after the package's hooks were removed")
	}
	if left, err := os.ReadFile(hooks); err != nil || strings.Contains(string(left), `"kontext"`) || !strings.Contains(string(left), "other-tool") {
		t.Fatalf("after removal: %s %v", left, err)
	}
	if heal() {
		t.Fatal("a second removal pass changed something")
	}
	if err := os.Remove(hooks); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, template, 0o644); err != nil {
		t.Fatal(err)
	}
	// Another binary (an old process after an upgrade, or a developer build)
	// writes nothing.
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

// The remover deletes the package's machine-wide hooks and then stops the
// daemon, sooner than its next pass a minute later. The daemon removes the
// user's hooks as it stops, before the binary they name is deleted.
func TestManagedDaemonRemovesItsHooksAsItStops(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the daemon heals hooks on macOS only")
	}
	home := t.TempDir()
	hermetic.SetHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	state := filepath.Join(home, ".gemini", "antigravity", "state.json")
	if err := os.MkdirAll(filepath.Dir(state), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "managed.json")
	if err := os.WriteFile(config, []byte(`{"version":"managed-install-v1","cloud_url":"https://api.kontext.dev","mode":"observe","agent":"claude","credentials":{"install_token_ref":"env:KONTEXT_INSTALL_TOKEN"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managedconfig.EnvPath, config)
	loaded, err := managedconfig.Load()
	if err != nil {
		t.Fatal(err)
	}
	binary := hermetic.KontextBinary(t, t.TempDir())
	previousBinary, previousExe := managedHookBinary, executablePath
	managedHookBinary, executablePath = binary, func() (string, error) { return binary, nil }
	t.Cleanup(func() { managedHookBinary, executablePath = previousBinary, previousExe })
	dropIn := filepath.Join(t.TempDir(), "20-kontext.json")
	swapManagedSettingsPaths(t, dropIn, filepath.Join(filepath.Dir(dropIn), "managed-settings.json"))
	template, err := claudemanaged.TemplateJSON(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, template, 0o644); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	rescanned := make(chan struct{}, 1)
	go func() {
		defer close(done)
		runHookWatch(ctx, loaded, diagnostic.Logger{}, func() {
			select {
			case rescanned <- struct{}{}:
			default:
			}
		})
	}()
	hooks := antigravitymanaged.UserHooksPath(home)
	select {
	case <-rescanned:
	case <-time.After(10 * time.Second):
		t.Fatal("the daemon installed nothing")
	}
	if _, err := os.Stat(hooks); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dropIn); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	if _, err := os.Lstat(hooks); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the stopped daemon left its hook: %v", err)
	}
}
