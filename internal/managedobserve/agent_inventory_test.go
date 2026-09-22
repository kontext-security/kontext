package managedobserve

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
)

func TestAgentInventoryRefresh(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, d := range agentinventory.Catalog {
		if d.ConfigEnv != "" {
			t.Setenv(d.ConfigEnv, "")
		}
	}
	t.Setenv("OPENCLAW_HOME", "")
	t.Setenv("KONTEXT_AGENT_INVENTORY_INTERVAL", "20ms")
	if err := os.Mkdir(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	holder := &agentInventoryHolder{}
	if _, ok := holder.Fact(); ok {
		t.Fatal("fact before scan")
	}
	ready, done := make(chan struct{}), make(chan struct{})
	dbPath := filepath.Join(home, "guard.db")
	go func() { defer close(done); holder.run(ctx, DaemonOptions{}, dbPath, ready) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("initial scan did not finish")
	}
	inv, ok := holder.Fact()
	if !ok || len(inv.Agents) != 1 || inv.Agents[0].ID != "cursor" {
		t.Fatalf("initial fact=%+v, %t", inv, ok)
	}
	if err := os.Remove(filepath.Join(home, ".cursor")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		current, _ := holder.Fact()
		if len(current.Agents) == 0 {
			if len(inv.Agents) != 1 {
				t.Fatal("refresh mutated earlier fact")
			}
			if saved := LoadAgentInventory(dbPath); saved == nil || len(saved.Agents) != 0 {
				t.Fatalf("breadcrumb=%+v", saved)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("inventory did not refresh")
}

func TestAgentWiring(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	previousDropIn, previousFile := managedSettingsDropInPath, managedSettingsFilePath
	managedSettingsDropInPath, managedSettingsFilePath = filepath.Join(home, "missing-dropin"), filepath.Join(home, "missing-file")
	t.Cleanup(func() { managedSettingsDropInPath, managedSettingsFilePath = previousDropIn, previousFile })
	evaluators := agentWiring(codexmanaged.InstallationPaths{SystemHooks: filepath.Join(home, "system-hooks.json"), UserHooks: filepath.Join(home, ".codex/hooks.json")}, nil)
	for _, id := range []string{"claude_code", "claude_cowork", "codex"} {
		if got := evaluators[id](); got != agentinventory.WiredNo {
			t.Fatalf("%s=%s", id, got)
		}
	}
	if err := os.WriteFile(managedSettingsFilePath, []byte(`{"hooks": {}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// A read failure is unknown, shared by both Claude variants.
	if err := os.Mkdir(managedSettingsDropInPath, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"claude_code", "claude_cowork"} {
		if got := evaluators[id](); got != agentinventory.WiredError {
			t.Fatalf("%s=%s", id, got)
		}
	}
	path, err := codexmanaged.UserHooksPath()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		data []byte
		want agentinventory.Wired
	}{
		{[]byte(`{`), agentinventory.WiredError},
		{[]byte(`{"hooks":{}}`), agentinventory.WiredNo},
		{mustCodexHooks(t), agentinventory.WiredYes},
	} {
		if err := os.WriteFile(path, tt.data, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := evaluators["codex"](); got != tt.want {
			t.Fatalf("codex=%s,want %s", got, tt.want)
		}
	}
}

func TestAgentWiringRecognizesSystemCodexHooks(t *testing.T) {
	dir := t.TempDir()
	paths := codexmanaged.InstallationPaths{SystemHooks: filepath.Join(dir, "system.json"), UserHooks: filepath.Join(dir, "user.json")}
	if err := os.WriteFile(paths.SystemHooks, mustCodexHooks(t), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.UserHooks, []byte(`{"hooks":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := agentWiring(paths, nil)["codex"](); got != agentinventory.WiredYes {
		t.Fatalf("wired=%s", got)
	}
	if err := os.Remove(paths.SystemHooks); err != nil {
		t.Fatal(err)
	}
	if got := agentWiring(paths, nil)["codex"](); got != agentinventory.WiredNo {
		t.Fatalf("wired=%s", got)
	}
}

func mustCodexHooks(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(codexmanaged.Template("/opt/homebrew/bin/kontext"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDoctorReadsInventoryWithoutScanning(t *testing.T) {
	e := newDoctorTestEnv(t)
	if err := os.Mkdir(filepath.Join(e.dir, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	_, report := printStatus(&out, "dev", e.options())
	if report.Agents != nil || !strings.Contains(out.String(), "agents: not scanned yet") {
		t.Fatalf("report=%+v, text=%s", report.Agents, &out)
	}
	inv := agentinventory.Inventory{Agents: []agentinventory.Agent{{ID: "cursor", ConfigPath: "~/.cursor", Wired: agentinventory.WiredUnsupported}}, ReportedAt: e.now.Add(-4 * time.Minute).Format(time.RFC3339), Incomplete: true}
	if err := writeJSONBreadcrumb(AgentInventoryPath(e.dbPath), inv); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	_, report = printStatus(&out, "dev", e.options())
	if report.Agents == nil || len(report.Agents.Agents) != 1 || !strings.Contains(out.String(), "Cursor (unsupported)") || !strings.Contains(out.String(), "(incomplete)") {
		t.Fatalf("report=%+v, text=%s", report.Agents, &out)
	}
	if err := os.WriteFile(AgentInventoryPath(e.dbPath), []byte(`{`), 0o600); err != nil {
		t.Fatal(err)
	}
	if LoadAgentInventory(e.dbPath) != nil {
		t.Fatal("corrupt breadcrumb must be absent")
	}
}

func TestCoworkInventoryUsesLatestSessionPlacement(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, d := range agentinventory.Catalog {
		if d.ConfigEnv != "" {
			t.Setenv(d.ConfigEnv, "")
		}
	}
	t.Setenv("OPENCLAW_HOME", "")
	sidecarDir := filepath.Join(home, "Library/Application Support/Claude/local-agent-mode-sessions/account-fixture/org-fixture")
	if err := os.MkdirAll(sidecarDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeSidecar := func(name string, createdAt int64, hostLoopMode bool) {
		t.Helper()
		data, err := json.Marshal(map[string]any{
			"createdAt": createdAt, "lastActivityAt": createdAt,
			"hostLoopMode": hostLoopMode, "cliSessionId": "host-hook",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sidecarDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	createdAt := time.Now().UnixMilli()
	writeSidecar("local_vm.json", createdAt, false)
	dbPath := filepath.Join(home, "guard.db")
	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithCancel(context.Background())
	holder := &agentInventoryHolder{}
	ready, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		holder.run(ctx, DaemonOptions{AgentInventoryInterval: 20 * time.Millisecond}, dbPath, ready)
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("initial scan did not finish")
	}
	inv, _ := holder.Fact()
	if len(inv.Agents) != 1 || inv.Agents[0].Sandboxed == nil || !*inv.Agents[0].Sandboxed {
		t.Fatalf("VM sidecar: %+v", inv)
	}
	// isCoworkHookContext emits "cowork"; the store canonicalizes it while the
	// sidecar keeps the same session ID.
	if _, err := store.EnsureObservedSession(ctx, "host-hook", "cowork", "/tmp"); err != nil {
		t.Fatal(err)
	}
	writeSidecar("local_host.json", createdAt+1, true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		inv, _ := holder.Fact()
		if len(inv.Agents) == 1 && inv.Agents[0].Sandboxed != nil && !*inv.Agents[0].Sandboxed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("newer host sidecar did not override the VM sidecar")
}

func TestAgentWiringCodexLayers(t *testing.T) {
	valid := mustCodexHooks(t)
	other, err := codexmanaged.TemplateJSON("/Applications/Kontext/runtime/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := codexmanaged.TemplateJSON("/enterprise/other-agent")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		system, user []byte
		want         agentinventory.Wired
	}{
		{"system only", valid, nil, agentinventory.WiredYes},
		{"user only", nil, valid, agentinventory.WiredYes},
		{"both same", valid, valid, agentinventory.WiredYes},
		{"both different", valid, other, agentinventory.WiredYes},
		{"foreign system with valid user", foreign, valid, agentinventory.WiredYes},
		{"valid system with foreign user", valid, foreign, agentinventory.WiredYes},
		{"malformed system with valid user", []byte(`{`), valid, agentinventory.WiredYes},
		{"valid system with malformed user", valid, []byte(`{`), agentinventory.WiredYes},
		{"foreign only", foreign, nil, agentinventory.WiredNo},
		{"both foreign", foreign, foreign, agentinventory.WiredNo},
		{"malformed only", nil, []byte(`{`), agentinventory.WiredError},
		{"neither", nil, nil, agentinventory.WiredNo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			paths := codexmanaged.InstallationPaths{SystemHooks: filepath.Join(dir, "system.json"), UserHooks: filepath.Join(dir, "user.json")}
			for path, raw := range map[string][]byte{paths.SystemHooks: tc.system, paths.UserHooks: tc.user} {
				if raw != nil {
					if err := os.WriteFile(path, raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if got := agentWiring(paths, nil)["codex"](); got != tc.want {
				t.Fatalf("wired=%s, want %s", got, tc.want)
			}
		})
	}
}
