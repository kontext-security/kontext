package agentauthority

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSession(t *testing.T, home, root, name string, modified time.Time, sidecar any) {
	t.Helper()
	data, err := json.Marshal(sidecar)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "Library/Application Support/Claude", root, "account", "org", name)
	writeFixture(t, home, strings.TrimPrefix(path, home+"/"), string(data))
	if err := os.Chtimes(path, modified, modified); err != nil {
		t.Fatal(err)
	}
}

func connector(uuid, name, url string) map[string]any {
	return map[string]any{"uuid": uuid, "name": name, "url": url, "tools": []any{map[string]any{"name": "t", "description": "long text"}}}
}

func TestConnectorsFromClaudeSessionFiles(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	linear := "9b52f6af-6583-4bbc-8dab-8a49ee4d6f30"
	// Older session: Linear under an old name, plus a connector with a bad id and a secret-bearing name.
	writeSession(t, home, "claude-code-sessions", "local_old.json", now.Add(-time.Hour), map[string]any{
		"remoteMcpServersConfig": []any{
			connector(linear, "Old Linear", "https://mcp.linear.app/sse"),
			connector("not-a-uuid", "Broken", "https://example.com/mcp"),
			connector("11111111-1111-1111-1111-111111111111", "token=abc", "https://example.com/mcp"),
		},
	})
	// Newest session wins; host only, never the path or query.
	writeSession(t, home, "claude-code-sessions", "local_new.json", now, map[string]any{
		"remoteMcpServersConfig": []any{connector(strings.ToUpper(linear), "Linear", "https://mcp.linear.app/mcp?tenant=secret")},
	})
	// Cowork stores the same list, sometimes keyed by id.
	writeSession(t, home, "local-agent-mode-sessions", "local_cowork.json", now, map[string]any{
		"remoteMcpServersConfig": map[string]any{"a": connector("74141c5c-1648-4b07-b960-6822acbe1b8e", "Gmail", "https://gmail.mcp.claude.com/mcp")},
	})
	// Only the newest eight files per root are read.
	for i := 0; i < 9; i++ {
		writeSession(t, home, "local-agent-mode-sessions", fmt.Sprintf("local_stale%d.json", i), now.Add(-time.Duration(48+i)*time.Hour), map[string]any{
			"remoteMcpServersConfig": []any{connector(fmt.Sprintf("00000000-0000-0000-0000-%012d", i), fmt.Sprintf("Stale %d", i), "https://stale.example.com")},
		})
	}
	// More files than one directory listing returns; the newest must still win.
	for i := 0; i < 520; i++ {
		writeSession(t, home, "claude-code-sessions", fmt.Sprintf("local_bulk%03d.json", i), now.Add(-72*time.Hour), map[string]any{})
	}
	writeSession(t, home, "claude-code-sessions", "local_zzz_newest.json", now.Add(time.Minute), map[string]any{
		"remoteMcpServersConfig": []any{connector("22222222-2222-2222-2222-222222222222", "Notion", "https://mcp.notion.com/mcp")},
	})
	agents := []AgentLocation{{"claude_code", "~/.claude"}, {"claude_cowork", "~/Library/Application Support/Claude/local-agent-mode-sessions"}}
	r := scan(context.Background(), home, Environment{}, agents, now, filepath.Join(home, "managed"))

	code := r.Agents[0].Connectors
	if len(code) != 2 || code[0].Name != "Notion" {
		t.Fatalf("newest session beyond the listing limit was not read: %+v", code)
	}
	code = code[1:]
	if code[0].UUID != linear || code[0].Name != "Linear" || code[0].URLHost == nil || *code[0].URLHost != "mcp.linear.app" || code[0].LastSeen == nil || *code[0].LastSeen != now.Format(time.RFC3339) {
		t.Fatalf("code tab connectors = %+v", code)
	}
	cowork := r.Agents[1].Connectors
	if len(cowork) != 8 || cowork[0].Name != "Gmail" {
		t.Fatalf("cowork connectors = %d %+v", len(cowork), cowork)
	}
	for _, c := range cowork {
		if c.Name == "Stale 7" || c.Name == "Stale 8" {
			t.Fatalf("read a session beyond the newest eight: %s", c.Name)
		}
	}
	data, _ := json.Marshal(r)
	for _, leaked := range []string{"tenant=secret", "/mcp", "long text", "token=abc"} {
		if strings.Contains(string(data), leaked) {
			t.Fatalf("report leaked %q", leaked)
		}
	}

	empty := scan(context.Background(), fixtureHome(t, "home_empty"), Environment{}, agents, now, filepath.Join(home, "managed"))
	if data, _ := json.Marshal(empty.Agents[0]); strings.Contains(string(data), "connectors") {
		t.Fatalf("empty scan sent a connectors field: %s", data)
	}
}

// Claude Desktop 3.x keeps Cowork agent sessions in <org>/agent/.
func TestConnectorsFromCoworkAgentSessionFiles(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	writeSession(t, home, "local-agent-mode-sessions", "agent/local_agent.json", now, map[string]any{
		"remoteMcpServersConfig": []any{connector("33333333-3333-3333-3333-333333333333", "Notion", "https://mcp.notion.com/mcp")},
	})
	agents := []AgentLocation{{"claude_cowork", "~/Library/Application Support/Claude/local-agent-mode-sessions"}}
	r := scan(context.Background(), home, Environment{}, agents, now, filepath.Join(home, "managed"))
	if got := r.Agents[0].Connectors; len(got) != 1 || got[0].Name != "Notion" {
		t.Fatalf("cowork agent session connectors = %+v", got)
	}
}
