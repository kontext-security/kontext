package toolcatalog

import (
	"strings"
	"testing"
)

func TestResolveProviderMCP(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		input   map[string]any
		want    string
		matched bool
	}{
		// Claude Code names claude.ai connectors mcp__claude_ai_<Name>__.
		{"atlassian primary write", "mcp__claude_ai_Atlassian__createJiraIssue", map[string]any{"cloudId": "c", "projectKey": "ENG"}, "atlassian-mcp/createJiraIssue", true},
		{"atlassian read", "mcp__atlassian__getJiraIssue", nil, "atlassian-mcp/getJiraIssue", true},
		{"atlassian v1 name", "mcp__atlassian__addCommentToJiraIssue", nil, "atlassian-mcp/addCommentToJiraIssue", true},
		{"distinctive name under any server", "mcp__work__deleteJiraIssue", nil, "atlassian-mcp/deleteJiraIssue", true},
		{"generic name needs a hinted server", "mcp__atlassian__getTeam", nil, "atlassian-mcp/getTeam", true},
		{"generic name elsewhere passes through", "mcp__people__getTeam", nil, "", false},
		{"hinted server new tool", "mcp__jira__archiveJiraIssue", nil, "atlassian-mcp/unrecognized", true},
		// Non-primary operations run through execute-family meta-tools; the
		// call is judged as the operation it names.
		{"execute destructive", "mcp__atlassian__executeDestructive", map[string]any{"name": "deleteJiraIssue", "cloudId": "c", "inputs": map[string]any{"issueIdOrKey": "ENG-1"}}, "atlassian-mcp/deleteJiraIssue", true},
		{"execute read", "mcp__claude_ai_Atlassian__executeRead", map[string]any{"name": "listJiraProjects"}, "atlassian-mcp/listJiraProjects", true},
		{"execute under renamed server", "mcp__corp__execute", map[string]any{"name": "updateJiraProject"}, "atlassian-mcp/updateJiraProject", true},
		{"execute unknown operation", "mcp__atlassian__executeWrite", map[string]any{"name": "purgeJiraSite"}, "atlassian-mcp/unrecognized", true},
		{"execute missing operation", "mcp__rovo__execute", map[string]any{}, "atlassian-mcp/unrecognized", true},
		{"distinctive dispatcher, unknown operation, any server", "mcp__3f2a9c__executeWrite", map[string]any{"name": "bulkEditJiraIssues"}, "atlassian-mcp/unrecognized", true},
		{"generic dispatcher, unknown operation, other server", "mcp__corp__execute", map[string]any{"name": "bulkEditJiraIssues"}, "", false},
		{"generic dispatcher, generic operation, other server", "mcp__runner__execute", map[string]any{"name": "fetch"}, "", false},
		{"hubspot manage tool under plugin server", "mcp__3f2a9c__manage_custom_properties", nil, "hubspot-mcp/manage_custom_properties", true},
		{"unrelated execute tool", "mcp__postgres__execute", map[string]any{"sql": "select 1"}, "", false},
		{"hubspot local", "mcp__hubspot__hubspot-batch-update-objects", nil, "hubspot-mcp/hubspot-batch-update-objects", true},
		{"hubspot remote", "mcp__claude_ai_HubSpot__manage_crm_objects", nil, "hubspot-mcp/manage_crm_objects", true},
		{"hubspot distinctive elsewhere", "mcp__plugin__search_crm_objects", nil, "hubspot-mcp/search_crm_objects", true},
		{"hubspot generic elsewhere", "mcp__plugin__get_user_details", nil, "", false},
		{"hubspot new tool", "mcp__HubSpot-EU__delete_crm_objects", nil, "hubspot-mcp/unrecognized", true},
		// A GitHub-named server stays on the GitHub catalog.
		{"github server", "mcp__github__get_me", map[string]any{}, "github-mcp/get_me", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, matched := Resolve(test.tool, "", test.input)
			if got != test.want || matched != test.matched {
				t.Fatalf("Resolve() = %q, %v; want %q, %v", got, matched, test.want, test.matched)
			}
		})
	}
}

func TestProviderKnownAndAccess(t *testing.T) {
	for id, want := range map[string]string{
		"atlassian-mcp/deleteJiraIssue":   AccessDelete,
		"atlassian-mcp/updateJiraProject": AccessAdmin,
		"atlassian-mcp/getJiraIssue":      AccessRead,
		"hubspot-mcp/manage_crm_objects":  AccessDelete, // annotated destructive upstream
		"hubspot-mcp/unrecognized":        "",
	} {
		if !Known(id) {
			t.Errorf("Known(%q) = false", id)
		}
		if got := ProviderToolAccess(id); got != want {
			t.Errorf("ProviderToolAccess(%q) = %q, want %q", id, got, want)
		}
	}
	for _, id := range []string{"atlassian-mcp/createJiraIssu", "hubspot-mcp/", "jira-mcp/createJiraIssue"} {
		if Known(id) {
			t.Errorf("Known(%q) = true", id)
		}
	}
}

func TestParseProviderCatalogRejectsUnclassifiedTools(t *testing.T) {
	for name, raw := range map[string]string{
		"unclassified": `{"provider":"x","toolIdPrefix":"x-mcp/","version":"1","serverNameHints":[],"sources":[],"dispatchers":[],"tools":[{"name":"a","product":"p","access":"unclassified"}]}`,
		"unsorted":     `{"provider":"x","toolIdPrefix":"x-mcp/","version":"1","serverNameHints":[],"sources":[],"dispatchers":[],"tools":[{"name":"b","product":"p","access":"read"},{"name":"a","product":"p","access":"read"}]}`,
		"reserved":     `{"provider":"x","toolIdPrefix":"x-mcp/","version":"1","serverNameHints":[],"sources":[],"dispatchers":[],"tools":[{"name":"unrecognized","product":"p","access":"read"}]}`,
		"unknown key":  `{"provider":"x","toolIdPrefix":"x-mcp/","version":"1","extra":1,"serverNameHints":[],"sources":[],"dispatchers":[],"tools":[]}`,
	} {
		if _, err := ParseProviderCatalog([]byte(raw)); err == nil {
			t.Errorf("%s: ParseProviderCatalog accepted %s", name, raw)
		}
	}
}

func TestProviderCatalogsAreLoaded(t *testing.T) {
	got := map[string]int{}
	for _, catalog := range Providers() {
		got[catalog.Provider] = len(catalog.Tools)
		if !strings.HasSuffix(catalog.ToolIDPrefix, "-mcp/") {
			t.Errorf("%s prefix %q", catalog.Provider, catalog.ToolIDPrefix)
		}
	}
	if got["atlassian"] == 0 || got["hubspot"] == 0 {
		t.Fatalf("provider catalogs = %v", got)
	}
}

func TestClassifyGitHubTools(t *testing.T) {
	tests := []struct {
		toolID string
		want   ProviderClassification
		ok     bool
	}{
		{"github-mcp/get_me", ProviderClassification{Provider: "github", Product: "users", Access: AccessRead}, true},
		{"github-mcp/update_issue_state", ProviderClassification{Provider: "github", Product: "issues", Access: AccessWrite}, true},
		{"github-mcp/merge_pull_request", ProviderClassification{Provider: "github", Product: "pull_requests", Access: AccessWrite}, true},
		{"github-mcp/actions_run_trigger", ProviderClassification{Provider: "github", Product: "actions", Access: AccessDelete}, true},
		{"github-mcp/delete_repository", ProviderClassification{Provider: "github", Product: "repository", Access: AccessAdmin}, true},
		{"github-mcp/unrecognized", ProviderClassification{}, false},
	}
	for _, test := range tests {
		got, ok := Classify(test.toolID)
		if ok != test.ok || got != test.want {
			t.Errorf("Classify(%q) = %+v, %v; want %+v, %v", test.toolID, got, ok, test.want, test.ok)
		}
	}
}

// Policies saved before GitHub was tiered forbid GitHub writes by name plus
// github-mcp/unrecognized. A tool they never named keeps reaching that
// fallback, and still carries its tier for the tier presets.
func TestUnnamedGitHubToolsReportUnrecognizedWithTheirTier(t *testing.T) {
	tests := []struct {
		toolName string
		input    map[string]any
		wantID   string
		want     ProviderClassification
	}{
		{"mcp__github__delete_repository", map[string]any{"owner": "o", "repo": "r"}, GitHubUnrecognizedTool, ProviderClassification{Provider: "github", Product: "repository", Access: AccessAdmin}},
		{"mcp__corp__actions_list", map[string]any{"method": "list_workflows", "owner": "o", "repo": "r"}, GitHubUnrecognizedTool, ProviderClassification{Provider: "github", Product: "actions", Access: AccessRead}},
		{"mcp__github__get_me", map[string]any{}, "github-mcp/get_me", ProviderClassification{Provider: "github", Product: "users", Access: AccessRead}},
		// Input that drifted from the pinned schema stays unrecognized for
		// id-based policies but keeps the tool's tier for the tier presets.
		{"mcp__github__create_branch", map[string]any{"owner": "o", "repo": "r", "branch": "b", "note": "x"}, GitHubUnrecognizedTool, ProviderClassification{Provider: "github", Product: "code", Access: AccessWrite}},
		{"mcp__github__delete_file", map[string]any{"owner": "o", "repo": "r"}, GitHubUnrecognizedTool, ProviderClassification{Provider: "github", Product: "code", Access: AccessDelete}},
	}
	for _, test := range tests {
		id, ok := Resolve(test.toolName, "", test.input)
		if !ok || id != test.wantID {
			t.Errorf("Resolve(%q) = %q, %v; want %q", test.toolName, id, ok, test.wantID)
		}
		got, ok := ClassifyCall(id, test.toolName, test.input)
		if !ok || got != test.want {
			t.Errorf("ClassifyCall(%q) = %+v, %v; want %+v", test.toolName, got, ok, test.want)
		}
	}
	if _, ok := ClassifyCall(GitHubUnrecognizedTool, "mcp__github__brand_new_tool", map[string]any{}); ok {
		t.Error("an uncatalogued GitHub tool must carry no tier")
	}
	if Known("github-mcp/delete_repository") {
		t.Error("the daemon never reports an unnamed GitHub tool by name")
	}
}

func TestResolveByServerURL(t *testing.T) {
	const (
		atlassianURL = "https://mcp.atlassian.com/v1/sse"
		hubspotURL   = "https://MCP.HubSpot.com./anthropic"
		githubURL    = "https://api.githubcopilot.com/mcp/"
		otherURL     = "https://mcp.linear.app/sse"
	)
	tests := []struct {
		name    string
		tool    string
		url     string
		input   map[string]any
		want    string
		matched bool
	}{
		// A generic name on a server with no name hint resolves by URL.
		{"atlassian generic tool, neutral name", "mcp__work__getTeam", atlassianURL, nil, "atlassian-mcp/getTeam", true},
		{"atlassian new tool, neutral name", "mcp__work__archiveJiraIssue", atlassianURL, nil, "atlassian-mcp/unrecognized", true},
		{"hubspot generic tool, case and trailing dot", "mcp__crm__get_user_details", hubspotURL, nil, "hubspot-mcp/get_user_details", true},
		// The URL decides over a conflicting name.
		{"atlassian URL named github", "mcp__github__get_me", atlassianURL, map[string]any{}, "atlassian-mcp/unrecognized", true},
		{"atlassian URL named hubspot", "mcp__hubspot__get_user_details", atlassianURL, nil, "atlassian-mcp/unrecognized", true},
		{"github URL named atlassian", "mcp__atlassian__get_me", githubURL, map[string]any{}, "github-mcp/get_me", true},
		{"github URL named hubspot, new tool", "mcp__hubspot__search_crm_objects", githubURL, nil, GitHubUnrecognizedTool, true},
		// A URL no catalog claims falls back to the name hints.
		{"unclaimed URL, hinted name", "mcp__jira__getTeam", otherURL, nil, "atlassian-mcp/getTeam", true},
		{"unclaimed URL, neutral name", "mcp__work__getTeam", otherURL, nil, "", false},
		{"lookalike host", "mcp__work__getTeam", "https://mcp.atlassian.com.evil.example/v1/sse", nil, "", false},
		{"not a URL", "mcp__work__getTeam", "npx mcp-remote", nil, "", false},
		{"no URL", "mcp__work__getTeam", "", nil, "", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, matched := Resolve(test.tool, test.url, test.input)
			if got != test.want || matched != test.matched {
				t.Fatalf("Resolve() = %q, %v; want %q, %v", got, matched, test.want, test.matched)
			}
		})
	}
}

// A server name that hints at a later catalog is held to that catalog
// before an earlier catalog's distinctive names are tried.
func TestResolveTriesNameHintedProvidersFirst(t *testing.T) {
	if got, ok := Resolve("mcp__hubspot__deleteJiraIssue", "", nil); !ok || got != "hubspot-mcp/unrecognized" {
		t.Fatalf("Resolve() = %q, %v; want hubspot-mcp/unrecognized", got, ok)
	}
}

// The vectors kontext-cloud pins in provider-tool-catalog.test.ts
// (kontext-cloud#1190): both sides must hash a catalog identically.
func TestProviderDigestMatchesCloudVectors(t *testing.T) {
	const base = `"provider":"databricks","toolIdPrefix":"databricks-mcp/","version":"2026-10-19","serverNameHints":["databricks"],"sources":[],` +
		`"tools":[{"name":"genie-space","product":"genie","access":"read"},{"name":"uc-function","product":"unity_catalog","access":"write"}]`
	tests := map[string]struct{ fields, want string }{
		"absent": {`"dispatchers":[]`, "e67172264aed3836a6753bb09bfed2c99269a755393f616b404fbf82b1a54be3"},
		"empty":  {`"dispatchers":[],"serverUrlHints":[],"urlKinds":[]`, "e67172264aed3836a6753bb09bfed2c99269a755393f616b404fbf82b1a54be3"},
		"unsorted with dispatcher": {
			`"serverUrlHints":[{"host":"dbc-1234.example.com","pathPrefix":"/api/2.0/mcp/"},{"host":"*.cloud.databricks.com","pathPrefix":"/api/2.0/mcp/"}],` +
				`"urlKinds":[{"pathPrefix":"/api/2.0/mcp/genie/","toolId":"databricks-mcp/genie-space"},{"pathPrefix":"/api/2.0/mcp/functions/","toolId":"databricks-mcp/uc-function"}],` +
				`"dispatchers":[{"name":"execute","operationField":"name"}]`,
			"68da7716c81c102552956a2f4dfef6ee087fc39bd1e85468983d3b222148634f",
		},
	}
	for name, test := range tests {
		catalog, err := ParseProviderCatalog([]byte("{" + base + "," + test.fields + "}"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := providerDigest(catalog); got != test.want {
			t.Errorf("%s: providerDigest() = %s, want %s", name, got, test.want)
		}
	}
}

func TestParseProviderCatalogRejectsBadURLFields(t *testing.T) {
	const head = `{"provider":"x","toolIdPrefix":"x-mcp/","version":"1","serverNameHints":[],"sources":[],"dispatchers":[],"tools":[{"name":"a","product":"p","access":"read"}],`
	for name, fields := range map[string]string{
		"uppercase host":       `"serverUrlHints":[{"host":"MCP.example.com","pathPrefix":"/"}]`,
		"inner wildcard":       `"serverUrlHints":[{"host":"mcp.*.example.com","pathPrefix":"/"}]`,
		"bare wildcard":        `"serverUrlHints":[{"host":"*.","pathPrefix":"/"}]`,
		"empty label":          `"serverUrlHints":[{"host":"mcp..example.com","pathPrefix":"/"}]`,
		"host with port":       `"serverUrlHints":[{"host":"mcp.example.com:443","pathPrefix":"/"}]`,
		"relative path":        `"serverUrlHints":[{"host":"mcp.example.com","pathPrefix":"api/"}]`,
		"path with tab":        `"serverUrlHints":[{"host":"mcp.example.com","pathPrefix":"/a\tb"}]`,
		"path with space":      `"urlKinds":[{"pathPrefix":"/a b","toolId":"x-mcp/a"}]`,
		"kind outside prefix":  `"urlKinds":[{"pathPrefix":"/a/","toolId":"y-mcp/a"}]`,
		"kind not catalogued":  `"urlKinds":[{"pathPrefix":"/a/","toolId":"x-mcp/b"}]`,
		"kind unrecognized":    `"urlKinds":[{"pathPrefix":"/a/","toolId":"x-mcp/unrecognized"}]`,
		"host not a string":    `"serverUrlHints":[{"host":1,"pathPrefix":"/"}]`,
		"unknown hint field":   `"serverUrlHints":[{"host":"mcp.example.com","pathPrefix":"/","port":1}]`,
		"tool id with newline": `"urlKinds":[{"pathPrefix":"/a/","toolId":"x-mcp/a\n"}]`,
	} {
		if _, err := ParseProviderCatalog([]byte(head + fields + "}")); err == nil {
			t.Errorf("%s: ParseProviderCatalog accepted %s", name, fields)
		}
	}
	if _, err := ParseProviderCatalog([]byte(head + `"serverUrlHints":[{"host":"*.example.com","pathPrefix":"/api/2.0/mcp/"}],"urlKinds":[{"pathPrefix":"/a/","toolId":"x-mcp/a"}]}`)); err != nil {
		t.Errorf("valid URL fields rejected: %v", err)
	}
}
