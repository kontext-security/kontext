package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
)

// databricksPresets are the seven Databricks presets (ENG-740) in the shape
// the cloud renders provider presets: an MCP clause on context.tool and a
// shell clause on context.shell facts. Each is evaluated on its own with the
// baseline permit, as a customer enables them.
var databricksPresets = map[string]string{
	"databricks-read-only": `forbid(principal, action == Kontext::Action::"ToolUse", resource)
when {
  (resource == Kontext::Tool::"shell" && context has shell && context.shell has facts && context.shell.facts.contains("databricks/write=true")) ||
  (context has tool && context.tool.provider == "databricks" && ["write", "delete", "admin"].contains(context.tool.access))
};`,
	"databricks-read-only-except-sql": `forbid(principal, action == Kontext::Action::"ToolUse", resource)
when {
  (resource == Kontext::Tool::"shell" && context has shell && context.shell has facts && context.shell.facts.contains("databricks/write=true") && !context.shell.facts.contains("databricks/product=sql")) ||
  (context has tool && context.tool.provider == "databricks" && context.tool.product != "sql" && ["write", "delete", "admin"].contains(context.tool.access))
};`,
	"block-databricks-deletion": `forbid(principal, action == Kontext::Action::"ToolUse", resource)
when {
  (resource == Kontext::Tool::"shell" && context has shell && context.shell has facts && context.shell.facts.contains("databricks/delete=true")) ||
  (context has tool && context.tool.provider == "databricks" && context.tool.access == "delete")
};`,
	"protect-databricks-administration": `forbid(principal, action == Kontext::Action::"ToolUse", resource)
when {
  (resource == Kontext::Tool::"shell" && context has shell && context.shell has facts && context.shell.facts.contains("databricks/admin=true")) ||
  (context has tool && context.tool.provider == "databricks" && context.tool.access == "admin")
};`,
	"protect-databricks-secrets": `forbid(principal, action == Kontext::Action::"ToolUse", resource)
when {
  (resource == Kontext::Tool::"shell" && context has shell && context.shell has facts && context.shell.facts.contains("databricks/product=secrets")) ||
  (context has tool && context.tool.provider == "databricks" && context.tool.product == "secrets")
};`,
	"protect-databricks-runs-and-deploys": `forbid(principal, action == Kontext::Action::"ToolUse", resource)
when {
  (resource == Kontext::Tool::"shell" && context has shell && context.shell has facts && context.shell.facts.contains("databricks/product=execution") && context.shell.facts.contains("databricks/write=true")) ||
  (context has tool && context.tool.provider == "databricks" && context.tool.product == "execution" && ["write", "delete", "admin"].contains(context.tool.access))
};`,
	"block-unrecognized-databricks-operations": `forbid(principal, action == Kontext::Action::"ToolUse", resource)
when {
  resource == Kontext::Tool::"databricks-mcp/unrecognized" ||
  (resource == Kontext::Tool::"shell" && context has shell && context.shell has facts && context.shell.facts.contains("databricks/route=unrecognized"))
};`,
}

func TestCedarDatabricksPresets(t *testing.T) {
	home := useMCPHome(t)
	const workspace = "https://dbc-1234.cloud.databricks.com"
	servers := `{"wh": {"type": "http", "url": "` + workspace + `/api/2.0/mcp/sql"},
"github": {"url": "` + workspace + `/api/2.0/mcp/sql"},
"genie": {"url": "` + workspace + `/api/2.0/mcp/genie/01ef"},
"fns": {"url": "` + workspace + `/api/2.0/mcp/functions/main/default"},
"vs": {"url": "` + workspace + `/api/2.0/mcp/vector-search/main/docs"},
"serving": {"url": "` + workspace + `/serving-endpoints/chat/invocations"}}`
	writeConfig(t, filepath.Join(home, ".claude.json"), `{"mcpServers": `+servers+`}`)
	writeConfig(t, filepath.Join(home, "Library/Application Support/Claude/claude_desktop_config.json"), `{"mcpServers": `+servers+`}`)
	codex := ""
	for name, path := range map[string]string{"wh": "/api/2.0/mcp/sql", "github": "/api/2.0/mcp/sql", "genie": "/api/2.0/mcp/genie/01ef", "fns": "/api/2.0/mcp/functions/main/default", "vs": "/api/2.0/mcp/vector-search/main/docs", "serving": "/serving-endpoints/chat/invocations"} {
		codex += "[mcp_servers." + name + "]\nurl = \"" + workspace + path + "\"\n"
	}
	writeConfig(t, filepath.Join(home, ".codex/config.toml"), codex)
	// A claude.ai Databricks connector in Claude Desktop: its tools carry
	// the connector UUID, and the session record has its URL.
	const connector = "c2be245b-9fd0-47e8-9a48-80c63e49e3fb"
	writeConfig(t, filepath.Join(home, "Library/Application Support/Claude/claude-code-sessions/acct/org/local_s.json"),
		`{"cliSessionId": "session-1", "remoteMcpServersConfig": [{"uuid": "`+connector+`", "name": "Databricks", "url": "`+workspace+`/ai-gateway/mcp-services/system.ai.dbsql"}]}`)

	const (
		readOnly   = "databricks-read-only"
		exceptSQL  = "databricks-read-only-except-sql"
		deletion   = "block-databricks-deletion"
		admin      = "protect-databricks-administration"
		secrets    = "protect-databricks-secrets"
		runs       = "protect-databricks-runs-and-deploys"
		unrecogniz = "block-unrecognized-databricks-operations"
	)
	sql := func(query string) map[string]any { return map[string]any{"query": query, "warehouse_id": "w"} }
	calls := []struct {
		name   string
		tool   string
		input  map[string]any
		denies []string
	}{
		{"select", "mcp__wh__execute_sql", sql("SELECT * FROM t"), []string{readOnly}},
		{"drop", "mcp__wh__execute_sql", sql("DROP TABLE t"), []string{readOnly, deletion}},
		{"grant", "mcp__wh__execute_sql", sql("GRANT SELECT ON TABLE t TO `u`"), []string{readOnly, admin}},
		// Known gap (ENG-734): delete and admin together report delete.
		{"create or replace", "mcp__wh__execute_sql", sql("CREATE OR REPLACE TABLE t AS SELECT 1"), []string{readOnly, deletion}},
		{"secret", "mcp__wh__execute_sql", sql("SELECT secret('scope', 'key')"), []string{readOnly, exceptSQL, secrets}},
		{"malformed SQL keeps write", "mcp__wh__execute_sql", sql("SELEC ((("), []string{readOnly}},
		{"missing query keeps write", "mcp__wh__execute_sql", map[string]any{}, []string{readOnly}},
		{"read-only SQL", "mcp__wh__execute_sql_read_only", sql("SELECT 1"), nil},
		{"read-only SQL with secret", "mcp__wh__execute_sql_read_only", sql("SELECT secret('s', 'k')"), []string{secrets}},
		{"poll", "mcp__wh__poll_sql_result", map[string]any{"statement_id": "s"}, nil},
		{"conflicting name github", "mcp__github__execute_sql", sql("DROP TABLE t"), []string{readOnly, deletion}},
		{"genie ask", "mcp__genie__genie_ask", map[string]any{"question": "q"}, nil},
		{"genie cancel", "mcp__genie__genie_cancel_response", map[string]any{}, []string{readOnly, exceptSQL}},
		{"uc function", "mcp__fns__main__default__refund", map[string]any{"id": 1}, []string{readOnly, exceptSQL, runs}},
		{"ai search", "mcp__vs__main__docs_index", map[string]any{"query": "q"}, nil},
		{"new tool on a Databricks server", "mcp__wh__run_python", map[string]any{}, []string{unrecogniz}},
		// Unidentified servers keep their raw names and are allowed.
		{"URL miss", "mcp__serving__execute_sql", sql("DROP TABLE t"), nil},
		{"unconfigured server", "mcp__warehouse__execute_sql", sql("DROP TABLE t"), nil},
	}
	desktop := []struct {
		name   string
		tool   string
		input  map[string]any
		denies []string
	}{
		{"desktop connector drop", "mcp__" + connector + "__execute_sql", sql("DROP TABLE t"), []string{readOnly, deletion}},
		{"desktop connector select", "mcp__" + connector + "__execute_sql", sql("SELECT 1"), []string{readOnly}},
	}
	for preset, forbid := range databricksPresets {
		policy := `@id("allow") permit(principal, action == Kontext::Action::"ToolUse", resource);
@id("` + preset + `") ` + forbid
		deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, policy)
		provider := newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
		for _, agent := range []string{"claude", "codex", "cowork"} {
			agentCalls := calls
			if agent != "codex" {
				agentCalls = append(agentCalls, desktop...)
			}
			for _, call := range agentCalls {
				want := risk.DecisionAllow
				for _, denying := range call.denies {
					if denying == preset {
						want = risk.DecisionDeny
					}
				}
				t.Run(preset+"/"+agent+"/"+call.name, func(t *testing.T) {
					event := cedarHookEvent(call.tool, call.input)
					event.Agent = agent
					decision, err := provider.DecideHook(context.Background(), event)
					if err != nil {
						t.Fatal(err)
					}
					if decision.Cedar == nil || decision.Cedar.Mapping.EvaluationState != cedareval.EvaluationStateEvaluated || decision.Cedar.EngineErrorCount != 0 {
						t.Fatalf("Cedar evidence = %#v, want evaluation without errors", decision.Cedar)
					}
					if decision.Decision != want {
						t.Fatalf("decision = %q (tool %q, %+v), want %q", decision.Decision, decision.Cedar.ToolID, decision.Cedar.Tool, want)
					}
				})
			}
		}
	}
}
