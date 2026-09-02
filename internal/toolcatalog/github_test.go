package toolcatalog

import (
	"encoding/json"
	"testing"
)

func TestResolveGitHubMCP(t *testing.T) {
	tests := []struct {
		name    string
		tool    string
		input   map[string]any
		want    string
		matched bool
	}{
		{"known read", "mcp__github__get_me", map[string]any{}, "github-mcp/get_me", true},
		{"known write", "mcp__github__create_issue", map[string]any{"owner": "acme", "repo": "api", "title": "bug"}, "github-mcp/create_issue", true},
		{"missing required", "mcp__github__create_issue", map[string]any{"owner": "acme"}, GitHubUnrecognizedTool, true},
		{"wrong type", "mcp__github__merge_pull_request", map[string]any{"owner": "acme", "repo": "api", "pullNumber": "1"}, GitHubUnrecognizedTool, true},
		{"number", "mcp__github__merge_pull_request", map[string]any{"owner": "acme", "repo": "api", "pullNumber": json.Number("1")}, "github-mcp/merge_pull_request", true},
		{"new field", "mcp__github__get_me", map[string]any{"future": true}, GitHubUnrecognizedTool, true},
		{"new GitHub tool", "mcp__github__future_tool", map[string]any{}, GitHubUnrecognizedTool, true},
		{"custom MCP", "mcp__custom__future_tool", map[string]any{}, "", false},
		// Operators rename the server; the catalog still recognises its tools.
		{"renamed server known read", "mcp__gh-enterprise__get_me", map[string]any{}, "github-mcp/get_me", true},
		{"renamed server known write", "mcp__acme_github__create_issue", map[string]any{"owner": "acme", "repo": "api", "title": "bug"}, "github-mcp/create_issue", true},
		{"unrelated server name known write", "mcp__work__merge_pull_request", map[string]any{"owner": "acme", "repo": "api", "pullNumber": json.Number("1")}, "github-mcp/merge_pull_request", true},
		{"github-named server broken schema", "mcp__GitHub-Prod__create_issue", map[string]any{"owner": "acme"}, GitHubUnrecognizedTool, true},
		{"github-named server new tool", "mcp__github-copilot__future_tool", map[string]any{}, GitHubUnrecognizedTool, true},
		// A catalogued tool name is held to its schema under any server name:
		// schema drift fails closed instead of resolving to unknown.
		{"renamed server missing required", "mcp__gh-enterprise__push_files", map[string]any{"owner": "o", "repo": "r", "branch": "main", "files": []any{}}, GitHubUnrecognizedTool, true},
		{"default server missing required", "mcp__github__push_files", map[string]any{"owner": "o", "repo": "r", "branch": "main", "files": []any{}}, GitHubUnrecognizedTool, true},
		{"renamed server wrong type", "mcp__gh__merge_pull_request", map[string]any{"owner": "acme", "repo": "api", "pullNumber": "1"}, GitHubUnrecognizedTool, true},
		{"unrelated server partial known fields", "mcp__work__create_issue", map[string]any{"title": "bug"}, GitHubUnrecognizedTool, true},
		// A same-named tool on an unrelated server whose input carries a field
		// GitHub never had is clearly another product's tool, not drift.
		{"unrelated server same-named tool other schema", "mcp__linear__create_issue", map[string]any{"teamId": "T1", "title": "bug"}, "", false},
		{"unrelated server foreign field only", "mcp__linear__list_issues", map[string]any{"assigneeId": "me"}, "", false},
		{"not an MCP tool", "Bash", map[string]any{"command": "git push"}, "", false},
		{"malformed MCP name", "mcp__github", map[string]any{}, "", false},
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

func TestCatalogDigestIsStable(t *testing.T) {
	const want = "cf87ee7a167f1f07bdc41450467708f832c9d8c4aaf20651a5d0df070d3de436"
	if got := Digest(); got != want {
		t.Fatalf("Digest() = %q, want %q", got, want)
	}
}

func TestOperations(t *testing.T) {
	if got := Operations(GitHubToolPrefix + "merge_pull_request"); len(got) != 1 || got[0] != "merge-pull-request" {
		t.Fatalf("Operations(merge_pull_request) = %v", got)
	}
	for _, toolID := range []string{GitHubToolPrefix + "update_pull_request", GitHubToolPrefix + "create_branch", GitHubUnrecognizedTool, "shell", ""} {
		if got := Operations(toolID); got != nil {
			t.Errorf("Operations(%q) = %v, want nil", toolID, got)
		}
	}
}
