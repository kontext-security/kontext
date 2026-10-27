package server

import (
	"context"
	"encoding/json"
	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/toolcatalog"
	"strings"
	"testing"
)

// These calls go through the hook decision with real catalog resolution.
// go test -json retains each expected/actual decision as a repeatable artifact.
func TestCommunityDatabricksPolicyDecisions(t *testing.T) {
	useMCPHome(t)
	for _, tc := range []struct {
		tool, preset string
		input        map[string]any
		blocked      bool
	}{
		{"update_repo", "block-databricks-deletion", nil, true},
		{"pull_repo", "block-databricks-deletion", nil, true},
		{"uninstall_library", "block-databricks-deletion", nil, true},
		{"uninstall_libraries", "block-databricks-deletion", nil, true},
		{"setup_user_workspace", "block-databricks-deletion", nil, false},
		{"sync_repo_and_run_notebook", "block-databricks-deletion", nil, true},
		{"sync_repo_and_run_notebook", "protect-databricks-runs-and-deploys", nil, true},
		{"download_file", "databricks-read-only", map[string]any{"dbfs_path": "dbfs:/tmp/source", "local_path": "dbfs:/tmp/target", "overwrite": true}, true},
		{"download_file", "block-databricks-deletion", map[string]any{"dbfs_path": "dbfs:/tmp/source", "local_path": "dbfs:/tmp/target", "overwrite": true}, true},
		{"download_file", "databricks-read-only", map[string]any{"dbfs_path": "dbfs:/tmp/source", "local_path": "./target"}, false},
		{"download_file", "block-databricks-data-export", map[string]any{"dbfs_path": "dbfs:/tmp/source", "local_path": "dbfs:/tmp/target"}, false},
		{"download_file", "block-databricks-data-export", map[string]any{"dbfs_path": "dbfs:/tmp/source", "local_path": "./target"}, true},
		{"download_file", "block-databricks-data-export", map[string]any{"dbfs_path": "dbfs:/tmp/source", "local_path": "DBFS:/tmp/target"}, true},
		{"download_file", "block-databricks-data-export", map[string]any{"dbfs_path": "dbfs:/tmp/source", "local_path": "dbfs:target"}, true},
		{"download_file", "databricks-read-only", map[string]any{"dbfs_path": "dbfs:/tmp/source", "local_path": "DBFS:/tmp/target"}, false},
		{"download_file", "block-databricks-deletion", map[string]any{"dbfs_path": "dbfs:/tmp/source", "local_path": "DBFS:/tmp/target"}, false},

		{"delete_cluster", "block-databricks-deletion", nil, true},
		{"delete_job", "block-databricks-deletion", nil, true},
		{"delete_workspace_item", "block-databricks-deletion", nil, true},
		{"delete_workspace_object", "block-databricks-deletion", nil, true},
		{"dbfs_delete", "block-databricks-deletion", nil, true},
		{"delete_file", "block-databricks-deletion", nil, true},
		{"create_job", "protect-databricks-administration", nil, true},
		{"update_job", "protect-databricks-administration", nil, true},
		{"run_job", "protect-databricks-runs-and-deploys", nil, true},
		{"run_notebook", "protect-databricks-runs-and-deploys", nil, true},
		{"list_clusters", "databricks-read-only", nil, false},
		{"list_jobs", "databricks-read-only", nil, false},
		{"list_tables", "databricks-read-only", nil, false},
		{"get_table_lineage", "block-unrecognized-databricks-operations", map[string]any{"full_name": "main.default.customers"}, false},
		{"mcp__unrelated__get_table_lineage", "block-unrecognized-databricks-operations", map[string]any{"full_name": "catalog/schema/table"}, false},
		{"get_table_lineage", "block-unrecognized-databricks-operations", map[string]any{"full_name": "../../../../2.0/secrets/get?scope=s&key=k"}, true},
		{"get_table_lineage", "block-unrecognized-databricks-operations", map[string]any{"full_name": "%2e%2e/%2e%2e/2.0/secrets/get"}, true},

		{"get_job_run_output", "databricks-read-only", nil, false},
		{"create_cluster", "databricks-read-only", nil, true},
		{"import_notebook", "block-databricks-deletion", nil, true},
		{"create_table", "block-databricks-deletion", map[string]any{"statement": "DROP TABLE t"}, true},
		{"create_table", "protect-databricks-administration", map[string]any{"statement": "GRANT SELECT ON TABLE t TO u"}, true},
		{"create_table", "block-databricks-deletion", map[string]any{"statement": "CREATE TABLE t(id INT)"}, false},
		{"execute_sql", "block-databricks-deletion", map[string]any{"params": map[string]any{"statement": "DROP TABLE t"}}, true},
		{"execute_sql", "block-databricks-data-export", map[string]any{"statement": "SELECT 1"}, false},
		{"execute_sql", "block-databricks-data-export", map[string]any{"params": map[string]any{"statement": "SELECT 1"}}, false},
		{"execute_sql", "block-databricks-data-export", map[string]any{"statement": "CREATE TABLE t LOCATION 's3://outside/dump' AS SELECT 1"}, true},
		{"execute_sql", "block-databricks-data-export", nil, true},
	} {
		for _, mode := range []cedareval.RolloutMode{cedareval.RolloutModeObserve, cedareval.RolloutModeEnforce} {
			t.Run(tc.tool+"/"+tc.preset+"/"+string(mode), func(t *testing.T) {
				source := databricksPresets[tc.preset]
				if tc.preset == "block-databricks-data-export" {
					source = `forbid(principal, action, resource) when { context has tool && context.tool.provider == "databricks" && context.tool.product == "export" };`
				}
				policy := `@id("default-permit") permit(principal, action, resource); @id("` + tc.preset + `") ` + source
				deployment := cedarTestDeployment(t, mode, policy)
				provider := newCedarPolicyProvider(staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
				toolName := tc.tool
				if !strings.HasPrefix(toolName, "mcp__") {
					toolName = "mcp__databricks__" + toolName
				}
				decision, err := provider.DecideHook(context.Background(), cedarHookEvent(toolName, tc.input))
				if err != nil {
					t.Fatal(err)
				}
				blocked := decision.Cedar != nil && decision.Cedar.Mapping.DerivedCedarAction == cedareval.DerivedCedarActionDeny
				want := risk.DecisionAllow
				if tc.blocked && mode == cedareval.RolloutModeEnforce {
					want = risk.DecisionDeny
				}
				receipt, _ := json.Marshal(map[string]any{"tool": tc.tool, "preset": tc.preset, "mode": mode, "expected_block": tc.blocked, "actual_block": blocked, "effective": decision.Decision})
				t.Log(string(receipt))
				if blocked != tc.blocked || decision.Decision != want {
					t.Fatalf("got %s/block=%t want %s/block=%t", decision.Decision, blocked, want, tc.blocked)
				}
			})
		}
	}
	// Generic names must never identify unrelated providers.
	for _, name := range []string{"list_clusters", "delete_job", "delete_file", "create_table"} {
		id, _ := toolcatalog.Resolve("mcp__unrelated__"+name, "", "", nil)
		if class, ok := toolcatalog.Classify(id); ok && class.Provider == "databricks" {
			t.Fatalf("unrelated tool resolved to %s", id)
		}
	}
}
