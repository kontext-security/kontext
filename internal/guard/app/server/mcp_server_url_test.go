package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/mcpconfig"
)

// TestMain keeps every test off the developer's own agent configs.
func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "kontext-mcp-home")
	if err != nil {
		panic(err)
	}
	mcpServers = &mcpconfig.Resolver{Home: home, Managed: filepath.Join(home, "managed-mcp.json")}
	code := m.Run()
	os.RemoveAll(home)
	os.Exit(code)
}

func useMCPHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	previous := mcpServers
	mcpServers = &mcpconfig.Resolver{Home: home, Managed: filepath.Join(home, "managed/managed-mcp.json")}
	t.Cleanup(func() { mcpServers = previous })
	return home
}

func writeConfig(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A provider server the operator gave a neutral name is identified by the
// URL in the agent's config, so its generic tools meet the tier presets
// instead of passing through under their raw names (the fail-open this
// closes). Servers that stay unidentified keep their raw name and are
// allowed.
func TestCedarResolvesMCPServersByConfiguredURL(t *testing.T) {
	const (
		connectorURL    = "c2be245b-9fd0-47e8-9a48-80c63e49e3fb"
		connectorName   = "7a1d0b3c-2e4f-4a5b-8c6d-0e1f2a3b4c5d"
		coworkConnector = "219594f1-0962-43db-80ef-5c9151f8459d"
	)
	home := useMCPHome(t)
	project := filepath.Join(home, "src/app")
	const atlassian = `{"type":"http","url":"https://mcp.atlassian.com/v1/mcp"}`
	writeConfig(t, filepath.Join(home, ".claude.json"), `{
  "mcpServers": {"work": `+atlassian+`, "tickets": {"url": "https://mcp.linear.app/sse"}, "bridge": {"command": "npx", "args": ["mcp-remote", "https://mcp.atlassian.com/v1/sse"]}},
  "projects": {
    "`+project+`": {"mcpServers": {"local.desk": `+atlassian+`}},
    "`+filepath.Join(home, "src/shadow")+`": {},
    "`+filepath.Join(home, "src/outer")+`": {"mcpServers": {"atlassian": {"url": "https://api.githubcopilot.com/mcp/"}, "work": {"url": "https://api.githubcopilot.com/mcp/"}}},
    "`+filepath.Join(home, "src/outer/repo")+`": {}
  }
}`)
	// The project .mcp.json overrides the user entry of the same name.
	writeConfig(t, filepath.Join(project, ".mcp.json"), `{"mcpServers": {"tickets": `+atlassian+`}}`)
	writeConfig(t, filepath.Join(home, "src/broken/.mcp.json"), `{"mcpServers": {`)
	writeConfig(t, filepath.Join(home, "managed/managed-mcp.json"), `{"mcpServers": {"corp": `+atlassian+`}}`)
	plugin := filepath.Join(home, ".claude/plugins/cache/market/jira-tools/1.0.0")
	writeConfig(t, filepath.Join(plugin, ".claude-plugin/plugin.json"), `{"name": "jira-tools"}`)
	writeConfig(t, filepath.Join(plugin, ".mcp.json"), `{"mcpServers": {"cloud": `+atlassian+`}}`)
	// A stdio entry in a higher scope shadows the user URL.
	writeConfig(t, filepath.Join(home, "src/shadow/.mcp.json"), `{"mcpServers": {"work": {"command": "npx", "args": ["github-mcp"]}}}`)
	// Two installations of one plugin name disagree about a server.
	for i, server := range []string{atlassian, `{"command": "npx"}`} {
		dup := filepath.Join(home, ".claude/plugins/cache", fmt.Sprintf("m%d", i), "dup-tools/1.0.0")
		writeConfig(t, filepath.Join(dup, ".claude-plugin/plugin.json"), `{"name": "dup-tools"}`)
		writeConfig(t, filepath.Join(dup, ".mcp.json"), `{"mcpServers": {"cloud": `+server+`}}`)
	}
	writeConfig(t, filepath.Join(home, ".claude/plugins/installed_plugins.json"), `{"plugins": {
  "jira-tools@market": [{"installPath": "`+plugin+`"}],
  "dup-tools@m0": [{"installPath": "`+filepath.Join(home, ".claude/plugins/cache/m0/dup-tools/1.0.0")+`"}],
  "dup-tools@m1": [{"installPath": "`+filepath.Join(home, ".claude/plugins/cache/m1/dup-tools/1.0.0")+`"}]
}}`)
	// Claude Desktop names a claude.ai connector's tools by its UUID and
	// records the connector in the session's record. Another session's
	// record, with the same UUID elsewhere, must not count.
	sessions := filepath.Join(home, "Library/Application Support/Claude/claude-code-sessions/acct/org")
	writeConfig(t, filepath.Join(sessions, "local_other.json"), `{"cliSessionId": "session-2", "remoteMcpServersConfig": [{"uuid": "`+connectorURL+`", "name": "Docs", "url": "https://api.githubcopilot.com/mcp/"}]}`)
	writeConfig(t, filepath.Join(sessions, "local_this.json"), `{"cliSessionId": "session-1", "title": "x", "remoteMcpServersConfig": [
  {"uuid": "`+connectorURL+`", "name": "Work", "url": "https://mcp.atlassian.com/v1/mcp", "tools": []},
  {"uuid": "`+connectorName+`", "name": "Atlassian", "url": "https://connector.example.com/mcp"}
]}`)
	writeConfig(t, filepath.Join(home, "Library/Application Support/Claude/local-agent-mode-sessions/acct/org/local_cowork.json"), `{"cliSessionId": "session-1", "remoteMcpServersConfig": [{"uuid": "`+coworkConnector+`", "name": "Atlassian"}]}`)
	writeConfig(t, filepath.Join(home, ".codex/config.toml"), "[mcp_servers.work]\nurl = \"https://mcp.atlassian.com/v1/mcp\"\n")
	writeConfig(t, filepath.Join(home, "Library/Application Support/Claude/claude_desktop_config.json"), `{"mcpServers": {"work": `+atlassian+`}}`)

	provider := atlassianReadOnlyProvider(t)
	// createTeam is a generic name: without a name hint only the URL makes
	// it Atlassian's write.
	write := map[string]any{"name": "platform"}
	tests := []struct {
		name  string
		agent string
		cwd   string
		tool  string
		want  risk.Decision
	}{
		{"claude user config", "claude", project, "mcp__work__createTeam", risk.DecisionDeny},
		{"claude user config, generic read", "claude", project, "mcp__work__getTeam", risk.DecisionAllow},
		{"claude project overrides user", "claude", project, "mcp__tickets__createTeam", risk.DecisionDeny},
		{"claude user entry outside the project", "claude", home, "mcp__tickets__createTeam", risk.DecisionAllow},
		{"claude local entry, normalized name", "claude", filepath.Join(project, "pkg"), "mcp__local_desk__createTeam", risk.DecisionDeny},
		{"claude managed config", "claude-code", "", "mcp__corp__createTeam", risk.DecisionDeny},
		{"claude plugin server", "claude", "", "mcp__plugin_jira-tools_cloud__createTeam", risk.DecisionDeny},
		{"codex", "codex", "", "mcp__work__createTeam", risk.DecisionDeny},
		{"cowork", "cowork", "", "mcp__work__createTeam", risk.DecisionDeny},
		// Unidentified servers: the raw name passes through and is allowed.
		{"stdio bridge", "claude", "", "mcp__bridge__createTeam", risk.DecisionAllow},
		{"malformed project config", "claude", filepath.Join(home, "src/broken"), "mcp__broken__createTeam", risk.DecisionAllow},
		{"stdio entry shadows a user URL", "claude", filepath.Join(home, "src/shadow"), "mcp__work__createTeam", risk.DecisionAllow},
		// Another recorded project's local entry above the session's project
		// is not active; where it disagrees the server name decides.
		{"ancestor project's local entry, hinted name", "claude", filepath.Join(home, "src/outer/repo"), "mcp__atlassian__createTeam", risk.DecisionDeny},
		{"ancestor project's local entry, neutral name", "claude", filepath.Join(home, "src/outer/repo/pkg"), "mcp__work__createTeam", risk.DecisionAllow},
		{"plugin installations disagree", "claude", "", "mcp__plugin_dup-tools_cloud__createTeam", risk.DecisionAllow},
		{"desktop connector by URL", "claude", "", "mcp__" + connectorURL + "__createTeam", risk.DecisionDeny},
		{"desktop connector by name", "claude", "", "mcp__" + connectorName + "__createTeam", risk.DecisionDeny},
		{"desktop connector in cowork", "cowork", "", "mcp__" + strings.ToUpper(connectorURL) + "__createTeam", risk.DecisionDeny},
		{"cowork connector by name only", "cowork", "", "mcp__" + coworkConnector + "__createTeam", risk.DecisionDeny},
		{"unknown desktop connector", "claude", "", "mcp__0d4c6e3a-1111-4222-8333-944445555666__createTeam", risk.DecisionAllow},
		{"unlisted server", "claude", project, "mcp__elsewhere__createTeam", risk.DecisionAllow},
		{"unknown agent", "gemini", project, "mcp__work__createTeam", risk.DecisionAllow},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event := cedarHookEvent(test.tool, write)
			event.Agent, event.CWD = test.agent, test.cwd
			decision, err := provider.DecideHook(context.Background(), event)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Decision != test.want {
				t.Fatalf("decision = %#v, want %q", decision, test.want)
			}
		})
	}

	// A session without a record leaves the connector unidentified.
	event := cedarHookEvent("mcp__"+connectorURL+"__createTeam", write)
	event.SessionID = "session-3"
	if decision, err := provider.DecideHook(context.Background(), event); err != nil || decision.Decision != risk.DecisionAllow {
		t.Fatalf("connector without a session record = %#v, %v; want allow", decision, err)
	}

	// A server identified before that no longer resolves (its entry was
	// removed) is unidentified again, and allowed.
	path := filepath.Join(home, "Library/Application Support/Claude/claude_desktop_config.json")
	writeConfig(t, path, `{"mcpServers": {}}`)
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(path, later, later); err != nil {
		t.Fatal(err)
	}
	event = cedarHookEvent("mcp__work__createTeam", write)
	event.Agent = "cowork"
	decision, err := provider.DecideHook(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionAllow {
		t.Fatalf("removed server decision = %#v, want allow", decision)
	}
}

func atlassianReadOnlyProvider(t *testing.T) PolicyProvider {
	t.Helper()
	policy := `@id("allow") permit(principal, action == Kontext::Action::"ToolUse", resource);
@id("atlassian-read-only") forbid(principal, action == Kontext::Action::"ToolUse", resource)
when { context has tool && context.tool.provider == "atlassian" && ["write", "delete", "admin"].contains(context.tool.access) };`
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, policy)
	return newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
}
