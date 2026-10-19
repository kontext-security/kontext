package server

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
)

// databricksPresets mirror the seven cloud Databricks presets (ENG-740) as
// the cloud renders a tier preset: a shell clause that fails closed when the
// shell context is missing, and an MCP clause on context.tool. Each is
// evaluated on its own with the baseline permit.
//
// ponytail: hand-rendered until kontext-cloud exports its rendered presets
// as a fixture (ENG-740); swap these for that file then.
var databricksPresets = map[string]string{
	"databricks-read-only": databricksTierPreset(`context.shell.facts.contains("databricks/write=true")`,
		`["write", "delete", "admin"].contains(context.tool.access)`),
	"databricks-read-only-except-sql": databricksTierPreset(`context.shell.facts.contains("databricks/write=true") && !context.shell.facts.contains("databricks/product=sql")`,
		`context.tool.product != "sql" && ["write", "delete", "admin"].contains(context.tool.access)`),
	"block-databricks-deletion": databricksTierPreset(`context.shell.facts.contains("databricks/delete=true")`,
		`context.tool.access == "delete"`),
	"protect-databricks-administration": databricksTierPreset(`context.shell.facts.contains("databricks/admin=true")`,
		`context.tool.access == "admin"`),
	"protect-databricks-secrets": databricksTierPreset(`context.shell.facts.contains("databricks/product=secrets")`,
		`context.tool.product == "secrets"`),
	"protect-databricks-runs-and-deploys": databricksTierPreset(`context.shell.facts.contains("databricks/product=execution") && context.shell.facts.contains("databricks/write=true")`,
		`context.tool.product == "execution" && ["write", "delete", "admin"].contains(context.tool.access)`),
	"block-unrecognized-databricks-operations": `forbid(principal, action == Kontext::Action::"ToolUse", resource)
when {
  resource == Kontext::Tool::"databricks-mcp/unrecognized" ||
  (resource == Kontext::Tool::"shell" && context has shell && ["databricks", "curl"].contains(context.shell.program) && context.shell.facts.contains("databricks/route=unrecognized"))
};`,
}

func databricksTierPreset(shell, tool string) string {
	return fmt.Sprintf(`forbid(principal, action == Kontext::Action::"ToolUse", resource)
when {
  (resource == Kontext::Tool::"shell" && (!(context has shell) || (context has shell && (!(context.shell has facts) || (context.shell has facts && %s))))) ||
  (context has tool && context.tool.provider == "databricks" && %s)
};`, shell, tool)
}

func databricksPresetProvider(t *testing.T, preset string) PolicyProvider {
	t.Helper()
	policy := `@id("allow") permit(principal, action == Kontext::Action::"ToolUse", resource);
@id("` + preset + `") ` + databricksPresets[preset]
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, policy)
	return newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
}

func decideDatabricks(t *testing.T, provider PolicyProvider, event risk.HookEvent) risk.Decision {
	t.Helper()
	decision, err := provider.DecideHook(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Cedar.EngineErrorCount != 0 || len(decision.Cedar.ContextDiagnostics) != 0 {
		t.Fatalf("decision = %#v, want no evaluation errors", decision)
	}
	return decision.Decision
}

const (
	dbAllow = risk.DecisionAllow
	dbDeny  = risk.DecisionDeny
)

// databricksSQLParity is shared with the MCP side (ENG-735): every SQL entry
// point, MCP execute_sql included, must reach the decision listed for each
// preset. Presets not listed allow. The one documented gap: an MCP call
// carries a single tier, so a statement that both deletes and administers is
// blocked by protect-databricks-administration through the shell only.
var databricksSQLParity = []struct {
	sql  string
	deny []string
}{
	{"SELECT * FROM main.sales.orders", []string{"databricks-read-only"}},
	{"INSERT INTO t VALUES (1)", []string{"databricks-read-only"}},
	{"DROP TABLE main.sales.orders", []string{"databricks-read-only", "block-databricks-deletion"}},
	{"DELETE FROM t WHERE id = 1", []string{"databricks-read-only", "block-databricks-deletion"}},
	{"GRANT SELECT ON TABLE t TO `users`", []string{"databricks-read-only", "protect-databricks-administration"}},
	{"ALTER CATALOG main OWNER TO `someone`", []string{"databricks-read-only", "protect-databricks-administration"}},
	{"DROP TABLE t; GRANT SELECT ON TABLE u TO `users`", []string{"databricks-read-only", "block-databricks-deletion", "protect-databricks-administration"}},
	{"SELECT secret('scope', 'key')", []string{"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-secrets"}},
	{"SELEC nonsense FRM", []string{"databricks-read-only"}},
}

func databricksSQLEntryPoints(sql string) map[string]risk.HookEvent {
	quoted := "'" + strings.ReplaceAll(sql, "'", `'\''`) + "'"
	body := fmt.Sprintf(`{"warehouse_id":"abc","statement":%q}`, sql)
	return map[string]risk.HookEvent{
		"aitools query":    cedarHookEvent("Bash", map[string]any{"command": "databricks experimental aitools tools query " + quoted}),
		"statement submit": cedarHookEvent("Bash", map[string]any{"command": "databricks experimental aitools tools statement submit -w abc " + quoted}),
		"databricks api":   cedarHookEvent("Bash", map[string]any{"command": "databricks api post /api/2.0/sql/statements --json '" + body + "'"}),
		"curl":             cedarHookEvent("Bash", map[string]any{"command": "curl -sS -X POST -H 'Authorization: Bearer x' --json '" + body + "' https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements"}),
		"codex query":      codexHookEvent("exec_command", map[string]any{"command": []any{"bash", "-lc", "databricks experimental aitools tools query " + quoted}}),
		"codex argv api":   codexHookEvent("shell", map[string]any{"command": []any{"databricks", "api", "post", "/api/2.0/sql/statements", "--json", body}}),
	}
}

func TestCedarDatabricksSQLParity(t *testing.T) {
	for preset := range databricksPresets {
		provider := databricksPresetProvider(t, preset)
		for _, test := range databricksSQLParity {
			want := dbAllow
			if containsString(test.deny, preset) {
				want = dbDeny
			}
			for entry, event := range databricksSQLEntryPoints(test.sql) {
				if got := decideDatabricks(t, provider, event); got != want {
					t.Errorf("%s, %s, %q: decision = %s, want %s", preset, entry, test.sql, got, want)
				}
			}
		}
	}
}

// TestCedarDatabricksPresets checks each preset on its own against the CLI,
// databricks api and curl, through Claude's Bash and Codex's shell tools.
func TestCedarDatabricksPresets(t *testing.T) {
	commands := map[string][]string{
		"databricks clusters list":                                                                      nil,
		"databricks bundle validate":                                                                    nil,
		"databricks auth login":                                                                         nil,
		"curl https://docs.databricks.com/index.html":                                                   nil,
		"databricks clusters create --json @c.json":                                                     {"databricks-read-only", "databricks-read-only-except-sql"},
		"databricks clusters delete 0123-abc":                                                           {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion"},
		"databricks catalogs update main --owner x":                                                     {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-administration"},
		"databricks secrets get-secret scope key":                                                       {"protect-databricks-secrets"},
		"databricks secrets put-secret scope key":                                                       {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-secrets"},
		"databricks jobs run-now 123":                                                                   {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-runs-and-deploys"},
		"databricks bundle deploy -t prod":                                                              {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-administration", "protect-databricks-runs-and-deploys"},
		"databricks bundle destroy --auto-approve":                                                      {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion", "protect-databricks-administration"},
		"databricks psql my-instance":                                                                   {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-runs-and-deploys"},
		"databricks fs rm dbfs:/tmp/x":                                                                  {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion"},
		"databricks api get /api/2.0/secrets/list?scope=s":                                              {"protect-databricks-secrets"},
		"curl -X POST -d '{}' https://adb-1.2.azuredatabricks.net/api/2.1/clusters/delete":              {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion"},
		"curl -X POST -d '{\"job_id\":1}' https://acme.databricks.com/api/2.2/jobs/run-now":             {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-runs-and-deploys"},
		"databricks frobnicate everything":                                                              {"block-unrecognized-databricks-operations"},
		"databricks api post /api/2.0/not-a-route":                                                      {"block-unrecognized-databricks-operations"},
		"curl https://dbc-1234.cloud.databricks.com/api/2.0/not-a-route":                                {"block-unrecognized-databricks-operations"},
		"curl -X POST -d '{}' https://dbc-1234.cloud.databricks.com/api/2.0/mcp/sql":                    {"block-unrecognized-databricks-operations"},
		"bash -lc 'databricks clusters delete 0123-abc'":                                                {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion"},
		"zsh -c 'databricks auth token -p prod'":                                                        {"protect-databricks-secrets"},
		"databricks experimental aitools tools query \"SELECT 1\"; databricks clusters delete 0123-abc": {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion"},
	}
	for preset := range databricksPresets {
		provider := databricksPresetProvider(t, preset)
		for command, deny := range commands {
			want := dbAllow
			if containsString(deny, preset) {
				want = dbDeny
			}
			events := map[string]risk.HookEvent{
				"claude":     cedarHookEvent("Bash", map[string]any{"command": command}),
				"codex bash": codexHookEvent("unified_exec", map[string]any{"command": []any{"bash", "-lc", command}}),
				"codex zsh":  codexHookEvent("shell", map[string]any{"command": []any{"/bin/zsh", "-lc", command}}),
			}
			for agent, event := range events {
				if got := decideDatabricks(t, provider, event); got != want {
					t.Errorf("%s, %s, %q: decision = %s, want %s", preset, agent, command, got, want)
				}
			}
		}
	}
}
