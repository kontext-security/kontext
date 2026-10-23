package server

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
)

// The presets are databricksPresets (databricks_presets_test.go), the cloud
// rendering each preset is evaluated as on its own with the baseline permit.
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
	// The MCP config lookup has a 250ms deadline, which a loaded test machine
	// can miss; the server is then unresolved. Retry that, not a decision.
	for retry := 0; retry < 3 && err == nil && strings.HasPrefix(event.ToolName, "mcp__") && !strings.HasPrefix(decision.Cedar.ToolID, "databricks-mcp/"); retry++ {
		decision, err = provider.DecideHook(context.Background(), event)
	}
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(event.ToolName, "mcp__") && !strings.HasPrefix(decision.Cedar.ToolID, "databricks-mcp/") {
		t.Fatalf("%s did not resolve to a Databricks MCP tool: %q", event.ToolName, decision.Cedar.ToolID)
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

// databricksSQLParity: every SQL entry point, the MCP execute_sql tool and
// the shell ones, must reach the decision listed for each preset. Presets not
// listed allow. SQL Kontext cannot read is delete and admin (ENG-792).
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
	{"SELEC nonsense FRM", []string{"databricks-read-only", "block-databricks-deletion", "protect-databricks-administration"}},
	{"EXECUTE IMMEDIATE 'DROP TABLE main.sales.orders'", []string{"databricks-read-only", "block-databricks-deletion", "protect-databricks-administration"}},
	// A proven tier does not vouch for the rest of the text.
	{"GRANT SELECT ON TABLE t TO `users`; EXECUTE IMMEDIATE 'DROP TABLE t'", []string{"databricks-read-only", "block-databricks-deletion", "protect-databricks-administration"}},
	{"SELECT * FROM read_files('/Volumes/main/raw/f')", []string{"databricks-read-only"}},
}

func databricksSQLEntryPoints(sql string) map[string]risk.HookEvent {
	shellQuote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
	quoted := shellQuote(sql)
	body := fmt.Sprintf(`{"warehouse_id":"abc","statement":%q}`, sql)
	return map[string]risk.HookEvent{
		"aitools query":    cedarHookEvent("Bash", map[string]any{"command": "databricks experimental aitools tools query " + quoted}),
		"statement submit": cedarHookEvent("Bash", map[string]any{"command": "databricks experimental aitools tools statement submit -w abc " + quoted}),
		"databricks api":   cedarHookEvent("Bash", map[string]any{"command": "databricks api post /api/2.0/sql/statements --json " + shellQuote(body)}),
		"curl":             cedarHookEvent("Bash", map[string]any{"command": "curl -sS -X POST -H 'Authorization: Bearer x' --json " + shellQuote(body) + " https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements"}),
		"codex query":      codexHookEvent("exec_command", map[string]any{"command": []any{"bash", "-lc", "databricks experimental aitools tools query " + quoted}}),
		"codex argv api":   codexHookEvent("shell", map[string]any{"command": []any{"databricks", "api", "post", "/api/2.0/sql/statements", "--json", body}}),
		"mcp execute_sql":  cedarHookEvent("mcp__wh__execute_sql", map[string]any{"query": sql, "warehouse_id": "abc"}),
	}
}

func TestCedarDatabricksSQLParity(t *testing.T) {
	// The MCP entry point is a configured Databricks SQL server.
	home := useMCPHome(t)
	writeConfig(t, filepath.Join(home, ".claude.json"), `{"mcpServers": {"wh": {"type": "http", "url": "https://dbc-1234.cloud.databricks.com/api/2.0/mcp/sql"}}}`)
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

// TestCedarDatabricksShellPresets checks each preset on its own against the
// CLI, databricks api and curl, through Claude's Bash and Codex's shell tools.
func TestCedarDatabricksShellPresets(t *testing.T) {
	commands := map[string][]string{
		"databricks clusters list":                                                          nil,
		"databricks bundle validate":                                                        nil,
		"databricks auth login":                                                             nil,
		"curl https://docs.databricks.com/index.html":                                       nil,
		"databricks clusters create --json @c.json":                                         {"databricks-read-only", "databricks-read-only-except-sql"},
		"databricks clusters delete 0123-abc":                                               {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion"},
		"databricks catalogs update main --owner x":                                         {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-administration"},
		"databricks secrets get-secret scope key":                                           {"protect-databricks-secrets"},
		"databricks secrets put-secret scope key":                                           {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-secrets"},
		"databricks jobs run-now 123":                                                       {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-runs-and-deploys"},
		"databricks bundle deploy -t prod":                                                  {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-administration", "protect-databricks-runs-and-deploys"},
		"databricks bundle destroy --auto-approve":                                          {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion", "protect-databricks-administration"},
		"databricks psql my-instance":                                                       {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-runs-and-deploys"},
		"databricks fs rm dbfs:/tmp/x":                                                      {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion"},
		"databricks api get /api/2.0/secrets/list?scope=s":                                  {"protect-databricks-secrets"},
		"curl -X POST -d '{}' https://adb-1.2.azuredatabricks.net/api/2.1/clusters/delete":  {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion"},
		"curl -X POST -d '{\"job_id\":1}' https://acme.databricks.com/api/2.2/jobs/run-now": {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-runs-and-deploys"},
		// A computed header or body is opaque: the route stays catalogued.
		`curl -sS -H "Authorization: Bearer $DATABRICKS_TOKEN" 'https://dbc-1234.cloud.databricks.com/api/2.2/jobs/get?job_id=1'`:                    nil,
		`curl -sS -X POST -H "Authorization: Bearer $DATABRICKS_TOKEN" -d '{"job_id":1}' https://dbc-1234.cloud.databricks.com/api/2.2/jobs/run-now`: {"databricks-read-only", "databricks-read-only-except-sql", "protect-databricks-runs-and-deploys"},
		// A Databricks command padded past the parse limit gets every tier.
		"databricks experimental aitools tools query 'DROP TABLE t /* " + strings.Repeat("x", 65<<10) + " */'": {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion", "protect-databricks-administration", "protect-databricks-secrets", "protect-databricks-runs-and-deploys", "block-unrecognized-databricks-operations"},
		"cat > notes.txt <<'EOF'\n" + strings.Repeat("x", 65<<10) + "\nEOF":                                    nil,
		"databricks frobnicate everything":                                                                     {"block-unrecognized-databricks-operations"},
		"databricks api post /api/2.0/not-a-route":                                                             {"block-unrecognized-databricks-operations"},
		"curl https://dbc-1234.cloud.databricks.com/api/2.0/not-a-route":                                       {"block-unrecognized-databricks-operations"},
		"curl -X POST -d '{}' https://dbc-1234.cloud.databricks.com/api/2.0/mcp/sql":                           {"block-unrecognized-databricks-operations"},
		"bash -lc 'databricks clusters delete 0123-abc'":                                                       {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion"},
		"zsh -c 'databricks auth token -p prod'":                                                               {"protect-databricks-secrets"},
		"databricks experimental aitools tools query \"SELECT 1\"; databricks clusters delete 0123-abc":        {"databricks-read-only", "databricks-read-only-except-sql", "block-databricks-deletion"},
		// SQL the projection does not read is delete and admin (ENG-792).
		"databricks api post /api/2.0/sql/statements --json @drop.json":                           {"databricks-read-only", "block-databricks-deletion", "protect-databricks-administration"},
		"curl -X POST -d @drop.json https://dbc-1234.cloud.databricks.com/api/2.0/sql/statements": {"databricks-read-only", "block-databricks-deletion", "protect-databricks-administration"},
		"databricks experimental aitools tools query --file drop.sql":                             {"databricks-read-only", "block-databricks-deletion", "protect-databricks-administration"},
		"cat drop.sql | databricks experimental aitools tools query":                              {"databricks-read-only", "block-databricks-deletion", "protect-databricks-administration"},
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
