package agentauthority

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCatalogConfigGuards(t *testing.T) {
	for _, tc := range []struct{ id, base, config string }{
		{"openclaw", ".openclaw", "openclaw.json"}, {"qwen_code", ".qwen", "settings.json"},
		{"goose", ".config/goose", "config.yaml"}, {"factory_droid", ".factory", "mcp.json"},
		{"devin_cli", ".config/devin", "mcp_config.json"}, {"kimi_code", ".kimi-code", "mcp.json"},
		{"auggie", ".augment", "settings.json"}, {"kilo", ".config/kilo", "kilo.jsonc"},
		{"crush", ".config/crush", "crush.json"}, {"junie", ".junie", "mcp/mcp.json"},
		{"grok_build", ".grok", "config.toml"}, {"hermes", ".hermes", "config.yaml"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			t.Setenv("CRUSH_GLOBAL_CONFIG", "")
			t.Setenv("KIMI_CODE_HOME", "")
			t.Setenv("KIMI_SHARE_DIR", "")
			home := fixtureHome(t, "home_"+tc.id)
			agents := []AgentLocation{{tc.id, filepath.Join(home, tc.base)}}
			scanner := new(Scanner)
			first := scanner.Scan(context.Background(), home, Environment{}, agents, fixtureTime)
			if len(first.Agents[0].MCPServers) != 1 {
				t.Fatalf("fixture MCP missing: %+v", first)
			}
			second := scanner.Scan(context.Background(), home, Environment{}, agents, fixtureTime)
			if len(second.Agents[0].MCPServers) != 1 {
				t.Fatal("cached MCP missing")
			}
			path := filepath.Join(home, tc.base, tc.config)
			if err := os.WriteFile(path, []byte("[invalid configuration"), 0600); err != nil {
				t.Fatal(err)
			}
			bad := scanner.Scan(context.Background(), home, Environment{}, agents, fixtureTime)
			if len(bad.Coverage.Errors) == 0 || len(bad.Agents[0].MCPServers) != 0 {
				t.Fatalf("bad config retained authority: %+v", bad)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(home, "target"), path); err != nil {
				t.Fatal(err)
			}
			blocked := scanner.Scan(context.Background(), home, Environment{}, agents, fixtureTime)
			if blocked.Coverage.SkippedFiles == 0 || len(blocked.Agents[0].MCPServers) != 0 {
				t.Fatal("symlink was not blocked")
			}
		})
	}
}

func TestCatalogOverridesAndLayers(t *testing.T) {
	t.Setenv("CLINE_DIR", "")
	t.Setenv("CLINE_DATA_DIR", "~/custom/cline")
	t.Setenv("CRUSH_GLOBAL_CONFIG", "~/custom/crush.json")
	home := fixtureHome(t, "home_empty")
	writeFixture(t, home, "custom/cline/settings/cline_mcp_settings.json", `{"mcpServers":{"sample":{"command":"npx"}}}`)
	writeFixture(t, home, "custom/crush.json", `{"mcp":{"sample":{"command":"npx"}}}`)
	r := scanFixture(home, []AgentLocation{{"cline", "~/.cline"}, {"crush", "~/.config/crush"}})
	for _, a := range r.Agents {
		if len(a.MCPServers) != 1 {
			t.Fatalf("override missing: %+v", a)
		}
	}
	t.Setenv("CRUSH_GLOBAL_CONFIG", "~/custom/crush-dir")
	writeFixture(t, home, "custom/crush-dir/crush.json", `{"mcp":{"sample":{"command":"node"}}}`)
	r = scanFixture(home, []AgentLocation{{"crush", "~/.config/crush"}})
	if len(r.Agents[0].MCPServers) != 1 || *r.Agents[0].MCPServers[0].Command != "node" {
		t.Fatal("directory override missing")
	}
	t.Setenv("CRUSH_GLOBAL_CONFIG", filepath.Join(t.TempDir(), "crush.json"))
	r = scanFixture(home, []AgentLocation{{"crush", "~/.config/crush"}})
	if r.Coverage.SkippedFiles == 0 {
		t.Fatal("outside-home override allowed")
	}
	for _, tc := range []struct{ id, base, first, last string }{
		{"devin_cli", ".config/devin", "config.json", "mcp_config.json"},
		{"kilo", ".config/kilo", "kilo.json", "kilo.jsonc"},
	} {
		key := "mcpServers"
		var first, second any
		first = map[string]any{"command": "old"}
		second = map[string]any{"command": "new"}
		if tc.id == "kilo" {
			key = "mcp"
			first = map[string]any{"command": []string{"old"}}
			second = map[string]any{"command": []string{"new"}}
		}
		for i, v := range []any{first, second} {
			file := tc.first
			if i == 1 {
				file = tc.last
			}
			data, _ := json.Marshal(map[string]any{key: map[string]any{"sample": v}})
			writeFixture(t, home, filepath.Join(tc.base, file), string(data))
		}
		scanner := new(Scanner)
		for range 2 {
			report := scanner.Scan(context.Background(), home, Environment{}, []AgentLocation{{tc.id, filepath.Join(home, tc.base)}}, fixtureTime)
			servers := report.Agents[0].MCPServers
			if len(servers) != 1 || *servers[0].Command != "new" || !strings.HasSuffix(servers[0].Source, tc.last) {
				t.Fatalf("layer merge: %+v", servers)
			}
		}
	}
}

func TestCatalogPluginGuardAndRedaction(t *testing.T) {
	home := fixtureHome(t, "home_hermes")
	writeFixture(t, home, ".hermes/plugins/secret/plugin.yaml", "name: 'ghp_"+strings.Repeat("A", 30)+"'")
	if err := os.Symlink(filepath.Join(home, ".hermes/plugins/sample"), filepath.Join(home, ".hermes/plugins/link")); err != nil {
		t.Fatal(err)
	}
	r := scanFixture(home, []AgentLocation{{"hermes", "~/.hermes"}})
	data, err := r.CanonicalJSON()
	if err != nil || strings.Contains(string(data), "ghp_") || len(r.Agents[0].Plugins) != 1 || r.Coverage.SkippedFiles == 0 {
		t.Fatalf("plugin guards: %+v %v", r, err)
	}
}

func TestEnvironmentOverridesCannotAuthorizeOutsideHome(t *testing.T) {
	for _, key := range []string{"CLINE_DATA_DIR", "CLINE_DIR", "OPENCODE_CONFIG_DIR", "KIMI_CODE_HOME", "KIMI_SHARE_DIR"} {
		t.Setenv(key, "")
	}
	home := fixtureHome(t, "home_empty")
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, outside, "globalState.json", `{"autoApprovalSettings":{"actions":{"executeAllCommands":true}}}`)
	writeFixture(t, outside, "settings/cline_mcp_settings.json", `{"mcpServers":{"outside":{"command":"npx"}}}`)
	writeFixture(t, outside, "data/globalState.json", `{"autoApprovalSettings":{"actions":{"executeAllCommands":true}}}`)
	writeFixture(t, outside, "data/settings/cline_mcp_settings.json", `{"mcpServers":{"outside":{"command":"npx"}}}`)
	writeFixture(t, outside, "opencode.json", `{"permission":{"bash":"allow"},"mcp":{"outside":{"command":["npx"]}}}`)
	writeFixture(t, outside, "config.toml", `default_permission_mode = "auto"`)
	writeFixture(t, outside, "mcp.json", `{"mcpServers":{"outside":{"command":"npx"}}}`)
	for _, tc := range []struct{ key, id, base string }{
		{"KIMI_CODE_HOME", "kimi_code", "~/.kimi-code"},
		{"KIMI_SHARE_DIR", "kimi_code", "~/.kimi"},
		{"CLINE_DATA_DIR", "cline", "~/.cline"},
		{"CLINE_DIR", "cline", "~/.cline"},
		{"OPENCODE_CONFIG_DIR", "opencode", "~/.config/opencode"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			t.Setenv(tc.key, outside)
			r := scanFixture(home, []AgentLocation{{tc.id, tc.base}})
			a := r.Agents[0]
			if r.Coverage.SkippedFiles == 0 || len(a.MCPServers) != 0 || a.Permissions.DefaultMode != nil {
				t.Fatalf("outside-home authority read: %+v", r)
			}
		})
	}
}

func TestKimiHomeOverrides(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	writeFixture(t, home, "current/config.toml", `default_permission_mode = "auto"`)
	writeFixture(t, home, "current/mcp.json", `{"mcpServers":{"sample":{"transport":"sse","url":"https://example.test/mcp?secret=hidden"}}}`)
	writeFixture(t, home, "legacy/config.toml", `default_yolo = false`)
	t.Setenv("KIMI_SHARE_DIR", "~/legacy")
	for _, current := range []string{"~/current", ""} {
		t.Setenv("KIMI_CODE_HOME", current)
		r := scanFixture(home, []AgentLocation{{"kimi_code", "~/.kimi-code"}})
		a := r.Agents[0]
		want := "default"
		if current != "" {
			want = "auto"
			if len(a.MCPServers) != 1 {
				t.Fatal("override MCP missing")
			}
		}
		if a.Permissions.DefaultMode == nil || *a.Permissions.DefaultMode != want {
			t.Fatalf("override mode: %+v", a)
		}
		data, err := r.CanonicalJSON()
		if err != nil || strings.Contains(string(data), "hidden") {
			t.Fatal("MCP query leaked")
		}
	}
}
