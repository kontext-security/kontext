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
			got, matched := Resolve(test.tool, test.input)
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
		"hubspot-mcp/manage_crm_objects":  AccessWrite,
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
