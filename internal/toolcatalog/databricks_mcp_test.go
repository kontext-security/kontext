package toolcatalog

import "testing"

func TestResolveDatabricksMCP(t *testing.T) {
	const (
		sqlURL   = "https://dbc-1234.cloud.databricks.com/api/2.0/mcp/sql"
		genieURL = "https://adb-1.11.azuredatabricks.net/api/2.0/mcp/genie/01ef"
		fnURL    = "https://acme.databricks.com/api/2.0/mcp/functions/main/default"
		proxy    = "https://dbc-1234.cloud.databricks.com/ai-gateway/mcp-services/"
	)
	pr := map[string]any{"owner": "o", "repo": "r", "title": "t"}
	tests := []struct {
		name    string
		tool    string
		url     string
		input   map[string]any
		want    string
		matched bool
	}{
		{"name hint", "mcp__databricks__execute_sql", "", nil, "databricks-mcp/execute_sql", true},
		{"name hint, new tool", "mcp__Databricks-Prod__run_python", "", nil, "databricks-mcp/unrecognized", true},
		{"URL, neutral name", "mcp__warehouse__execute_sql", sqlURL, nil, "databricks-mcp/execute_sql", true},
		{"URL, read-only SQL", "mcp__warehouse__execute_sql_read_only", sqlURL, nil, "databricks-mcp/execute_sql_read_only", true},
		{"azure genie", "mcp__space__genie_cancel_response", genieURL, nil, "databricks-mcp/genie_cancel_response", true},
		{"older genie tool", "mcp__space__query_space", genieURL, nil, "databricks-mcp/query_space", true},
		{"govcloud host", "mcp__w__execute_sql", "https://dbc-9.cloud.databricks.us/api/2.0/mcp/sql", nil, "databricks-mcp/execute_sql", true},
		{"sandbox or web search, not catalogued yet", "mcp__w__run_code", sqlURL, nil, "databricks-mcp/unrecognized", true},
		// URL kinds name the tool whatever the workspace calls it.
		{"UC function", "mcp__fns__main__default__get_weather", fnURL, nil, "databricks-mcp/uc-function", true},
		{"UC function named like a read tool", "mcp__fns__execute_sql_read_only", fnURL, nil, "databricks-mcp/uc-function", true},
		{"vector search", "mcp__vs__main__docs_index", "https://dbc-1.cloud.databricks.com/api/2.0/mcp/vector-search/main/docs", nil, "databricks-mcp/ai-search", true},
		{"ai search", "mcp__vs__docs", "https://dbc-1.cloud.databricks.com/api/2.0/mcp/ai-search/main", nil, "databricks-mcp/ai-search", true},
		// The AI Gateway proxies route to the proxied provider's catalog.
		{"github proxy", "mcp__gw__create_issue", proxy + "system.ai.github", pr, "github-mcp/create_issue", true},
		{"github proxy, new tool", "mcp__gw__future_tool", proxy + "system.ai.github/", nil, GitHubUnrecognizedTool, true},
		{"atlassian proxy, generic tool", "mcp__gw__getTeam", proxy + "system.ai.atlassian", nil, "atlassian-mcp/getTeam", true},
		{"atlassian proxy, new tool", "mcp__gw__purgeSite", proxy + "system.ai.atlassian", nil, "atlassian-mcp/unrecognized", true},
		{"other registered service", "mcp__gw__lookup", proxy + "main.default.crm", nil, "databricks-mcp/unrecognized", true},
		{"other registered service, catalogued name", "mcp__gw__execute_sql", proxy + "main.default.crm", nil, "databricks-mcp/unrecognized", true},
		{"other system service, catalogued name", "mcp__gw__genie_ask", proxy + "system.ai.other", nil, "databricks-mcp/unrecognized", true},
		{"databricks SQL service", "mcp__gw__execute_sql", proxy + "system.ai.dbsql", nil, "databricks-mcp/execute_sql", true},
		{"databricks SQL service, new tool", "mcp__gw__run", proxy + "system.ai.dbsql", nil, "databricks-mcp/unrecognized", true},
		{"lookalike proxy service", "mcp__gw__create_issue", proxy + "system.ai.github_enterprise", pr, "databricks-mcp/unrecognized", true},
		// Conflicting names: the URL decides.
		{"databricks URL named github", "mcp__github__execute_sql", sqlURL, nil, "databricks-mcp/execute_sql", true},
		{"databricks URL named github, github tool", "mcp__github__create_issue", sqlURL, pr, "databricks-mcp/unrecognized", true},
		{"databricks URL named atlassian", "mcp__atlassian__execute_sql", sqlURL, nil, "databricks-mcp/execute_sql", true},
		{"github URL named databricks", "mcp__databricks__get_me", "https://api.githubcopilot.com/mcp/", map[string]any{}, "github-mcp/get_me", true},
		{"atlassian URL named databricks", "mcp__databricks__execute_sql", "https://mcp.atlassian.com/v1/mcp", nil, "atlassian-mcp/unrecognized", true},
		// Unidentified: the raw name passes through.
		{"generic name, no hint, no URL", "mcp__postgres__execute_sql", "", nil, "", false},
		{"generic name, unclaimed URL", "mcp__wh__execute_sql", "https://warehouse.example.com/mcp", nil, "", false},
		{"databricks host, not an MCP path", "mcp__wh__execute_sql", "https://www.databricks.com/blog", nil, "", false},
		{"distinctive genie name anywhere", "mcp__space__genie_ask", "", nil, "databricks-mcp/genie_ask", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, matched := Resolve(test.tool, test.url, "", test.input)
			if got != test.want || matched != test.matched {
				t.Fatalf("Resolve() = %q, %v; want %q, %v", got, matched, test.want, test.matched)
			}
		})
	}
}

func TestClassifyDatabricksSQLCall(t *testing.T) {
	tests := []struct {
		name   string
		toolID string
		input  map[string]any
		want   ProviderClassification
	}{
		{"select", databricksExecuteSQL, map[string]any{"query": "SELECT 1"}, ProviderClassification{"databricks", "sql", AccessWrite}},
		{"drop", databricksExecuteSQL, map[string]any{"query": "DROP TABLE t"}, ProviderClassification{"databricks", "sql", AccessDelete}},
		{"grant", databricksExecuteSQL, map[string]any{"query": "GRANT SELECT ON TABLE t TO `u`"}, ProviderClassification{"databricks", "sql", AccessAdmin}},
		{"delete and admin reports delete", databricksExecuteSQL, map[string]any{"query": "CREATE OR REPLACE TABLE t AS SELECT 1"}, ProviderClassification{"databricks", "sql", AccessDelete}},
		{"secret", databricksExecuteSQL, map[string]any{"query": "SELECT secret('scope', 'key')"}, ProviderClassification{"databricks", "secrets", AccessWrite}},
		{"unrecognized SQL keeps write", databricksExecuteSQL, map[string]any{"query": "SELEC garbage ("}, ProviderClassification{"databricks", "sql", AccessWrite}},
		{"missing query keeps write", databricksExecuteSQL, map[string]any{}, ProviderClassification{"databricks", "sql", AccessWrite}},
		{"non-string query keeps write", databricksExecuteSQL, map[string]any{"query": []any{"DROP TABLE t"}}, ProviderClassification{"databricks", "sql", AccessWrite}},
		{"read-only select stays read", databricksExecuteSQLReadOnly, map[string]any{"query": "SELECT 1"}, ProviderClassification{"databricks", "sql", AccessRead}},
		{"read-only drop is raised", databricksExecuteSQLReadOnly, map[string]any{"query": "DROP TABLE t"}, ProviderClassification{"databricks", "sql", AccessDelete}},
		{"read-only delete and admin reports delete", databricksExecuteSQLReadOnly, map[string]any{"query": "CREATE OR REPLACE TABLE t AS SELECT 1"}, ProviderClassification{"databricks", "sql", AccessDelete}},
		{"read-only secret", databricksExecuteSQLReadOnly, map[string]any{"query": "SELECT secret('s', 'k')"}, ProviderClassification{"databricks", "secrets", AccessRead}},
		{"uc function", "databricks-mcp/uc-function", nil, ProviderClassification{"databricks", "execution", AccessWrite}},
		{"ai search", "databricks-mcp/ai-search", nil, ProviderClassification{"databricks", "ai", AccessRead}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := ClassifyCall(test.toolID, "mcp__databricks__x", test.input)
			if !ok || got != test.want {
				t.Fatalf("ClassifyCall() = %+v, %v; want %+v", got, ok, test.want)
			}
		})
	}
	if _, ok := ClassifyCall("databricks-mcp/unrecognized", "mcp__databricks__run", nil); ok {
		t.Fatal("an uncatalogued Databricks tool must carry no tier")
	}
}
