package agentauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var fixtureTime = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

func fixtureHome(t *testing.T, name string) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join("testdata", name)
	err = filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(source, path)
		dest := filepath.Join(home, rel)
		if entry.IsDir() {
			return os.MkdirAll(dest, 0700)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		data = bytes.ReplaceAll(data, []byte("{{HOME}}"), []byte(home))
		if err = os.WriteFile(dest, data, 0600); err != nil {
			return err
		}
		return os.Chtimes(dest, fixtureTime, fixtureTime)
	})
	if err != nil {
		t.Fatal(err)
	}
	return home
}
func writeFixture(t *testing.T, home, path, data string) {
	t.Helper()
	path = filepath.Join(home, path)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, fixtureTime, fixtureTime); err != nil {
		t.Fatal(err)
	}
}
func scanFixture(home string, agents []AgentLocation) Report {
	return scan(context.Background(), home, Environment{UID: 501, Admin: true}, agents, fixtureTime, filepath.Join(home, "managed"))
}
func TestGoldenHomes(t *testing.T) {
	for _, name := range []string{"home_claude_full", "home_codex", "home_desktop", "home_generic", "home_empty", "home_planted_token", "home_symlink_to_root", "home_huge_settings", "home_many_files", "home_malformed_json", "home_malformed_toml"} {
		t.Run(name, func(t *testing.T) {
			home := fixtureHome(t, name)
			agents := []AgentLocation{{"claude_code", "~/.claude"}}
			switch name {
			case "home_codex", "home_malformed_toml":
				agents = []AgentLocation{{"codex", "~/.codex"}}
			case "home_desktop":
				agents = []AgentLocation{{"claude_cowork", "~/Library/Application Support/Claude/local-agent-mode-sessions"}}
			case "home_generic":
				agents = []AgentLocation{{"cursor", "~/.cursor"}, {"amp", "~/.config/amp"}, {"opencode", "~/.config/opencode"}, {"goose", "~/.config/goose"}}
			case "home_empty":
				agents = nil
			case "home_planted_token":
				token := "ghp_" + strings.Repeat("A", 30)
				data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{"github": map[string]any{"command": "npx", "args": []string{token}, "env": map[string]string{"TOKEN": token}}}, "projects": map[string]any{filepath.Join(home, "repo"): map[string]any{}}})
				writeFixture(t, home, ".claude.json", string(data))
				writeFixture(t, home, "repo/.env", "API_TOKEN="+token)
				writeFixture(t, home, ".npmrc", "//registry.npmjs.org/:_authToken="+token)
			case "home_symlink_to_root":
				path := filepath.Join(home, ".claude/plugins/cache/root")
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/", path); err != nil {
					t.Fatal(err)
				}
				index, _ := json.Marshal(map[string]any{"plugins": map[string]any{"escape@local": []any{map[string]string{"installPath": path}}}})
				writeFixture(t, home, ".claude/plugins/installed_plugins.json", string(index))
			case "home_huge_settings":
				writeFixture(t, home, ".claude/settings.json", strings.Repeat(" ", 2*1024*1024))
			case "home_many_files":
				for i := 0; i < 5000; i++ {
					writeFixture(t, home, filepath.Join(".claude/skills", string(rune(0x4E00+i)), "SKILL.md"), "# Skill\n")
				}
			}
			report := scanFixture(home, agents)
			if name == "home_many_files" {
				// The bounded directory read returns a filesystem-dependent subset.
				// Verify the cap and provenance; normalize only the selected names.
				skills := report.Agents[0].Skills
				if len(skills) != maxFiles-1 {
					t.Fatalf("read %d skills, want %d", len(skills), maxFiles-1)
				}
				seen := make(map[string]bool)
				for i, skill := range skills {
					runes := []rune(skill.Name)
					if len(runes) != 1 || runes[0] < 0x4E00 || runes[0] >= 0x4E00+5000 || seen[skill.Name] || skill.Source != "~/.claude/skills" {
						t.Fatalf("unexpected skill: %+v", skill)
					}
					seen[skill.Name] = true
					skills[i].Name = fmt.Sprintf("skill-%03d", i)
				}
				report.Hash, _ = report.ContentHash()
			}
			data, err := report.CanonicalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if name == "home_planted_token" && bytes.Contains(data, []byte("ghp_")) {
				t.Fatal("secret escaped")
			}
			if strings.HasPrefix(name, "home_symlink") || name == "home_huge_settings" || name == "home_many_files" {
				if !report.Truncated && report.Coverage.SkippedFiles == 0 {
					t.Fatal("read guard did not report its limit")
				}
			}
			if len(data) > maxReportBytes {
				t.Fatalf("report has %d bytes", len(data))
			}
			golden := filepath.Join("testdata", name+".golden.json")
			if os.Getenv("UPDATE_AUTHORITY_GOLDENS") == "1" {
				if err := os.WriteFile(golden, append(data, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			expected, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bytes.TrimSpace(expected), data) {
				t.Fatalf("report differs from %s", golden)
			}
		})
	}
}
func TestContractRoundTrip(t *testing.T) {
	data, err := os.ReadFile("testdata/contract/authority-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if err = json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	actual, err := report.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(append(actual, '\n'), data) {
		t.Fatal("contract round trip changed bytes")
	}
	hash, err := report.ContentHash()
	if err != nil || hash != report.Hash {
		t.Fatal("contract hash differs")
	}
}
func TestParentSymlinkAndOutsideRoot(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	other, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, other, "secret/settings.json", `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	if err = os.Symlink(filepath.Join(other, "secret"), filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	r := scanFixture(home, []AgentLocation{{"claude_code", "~/.claude"}, {"codex", other}})
	if r.Agents[0].Permissions.DefaultMode != nil || r.Coverage.SkippedFiles == 0 {
		t.Fatal("symlink or outside root was accepted")
	}
}
func TestCancelledScan(t *testing.T) {
	home := fixtureHome(t, "home_claude_full")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := scan(ctx, home, Environment{}, []AgentLocation{{"claude_code", "~/.claude"}}, fixtureTime, filepath.Join(home, "managed"))
	if !r.Truncated {
		t.Fatal("cancelled scan is not truncated")
	}
}
func TestSecretArgumentsAndPermissionRules(t *testing.T) {
	for _, arg := range []string{"ghp_123", "token=private", "--AuthToken=secret", "--API-KEY=private", "PASSWD=private", "Bearer abc", "-----BEGIN KEY"} {
		if safeArg(arg) != "" {
			t.Errorf("kept secret arg %q", arg)
		}
	}
	for _, arg := range []string{"/Users/someone/file", "--config=/etc/file", "https://person:password@example.test", "https://person:password@%invalid"} {
		if safeArg(arg) != "<redacted>" {
			t.Errorf("kept private path or url %q", arg)
		}
	}
	for _, args := range [][]string{{"--password", "P@ssw0rd123"}, {"--TOKEN", "P@ssw0rd123"}, {"--api-key", "P@ssw0rd123"}, {"--AuthToken=secret"}} {
		if got := safeArgs(append(args, "--verbose")); len(got) != 1 || got[0] != "--verbose" {
			t.Fatalf("kept secret arguments: %q", got)
		}
	}
	for _, tc := range []struct{ args, want []string }{
		{[]string{"--tokenizer", "bert"}, []string{"--tokenizer", "bert"}},
		{[]string{"--no-token", "x"}, []string{"--no-token", "x"}},
		{[]string{"--NO_TOKEN", "x"}, []string{"--NO_TOKEN", "x"}},
		{[]string{"--secretsfile", "settings"}, []string{"--secretsfile", "settings"}},
		{[]string{"--token-count", "3"}, []string{"--token-count", "3"}},
		{[]string{"--key", "name"}, []string{"--key", "name"}},
		{[]string{"--auth-token", "abc"}, nil},
		{[]string{"--client-secret", "abc"}, nil},
		{[]string{"--apikey", "abc"}, nil},
		{[]string{"--api_key", "abc"}, nil},
		{[]string{"--passwd", "abc"}, nil},
		{[]string{"--password"}, nil},
		{[]string{"--password", "--tokenizer", "bert"}, []string{"--tokenizer", "bert"}},
		{[]string{"--password=value", "--token=value", "--verbose"}, []string{"--verbose"}},
	} {
		if got := safeArgs(tc.args); !slices.Equal(got, tc.want) {
			t.Errorf("safeArgs(%q) = %q, want %q", tc.args, got, tc.want)
		}
	}
	if pattern := "Bash(tool --tokenizer bert:*)"; safeGrant(pattern) != pattern {
		t.Errorf("changed non-secret permission grant: %q", safeGrant(pattern))
	}
	for pattern, want := range map[string]string{"Bash(*)": "any_shell", "Bash(python3:*)": "any_shell", "Bash(sudo:*)": "sudo", "Bash(rm:*)": "delete", "Bash(chmod:*)": "ownership", "WebFetch": "network", "Bash(git push --force:*)": "git_force", "Bash(pkill:*)": "kill", "Bash(git status:*)": "", "Bash(curl:https://*)": "network", "Bash(wget:*)": "network", "Bash(nc)": "network", "Bash(ssh -v)": "network", "Bash(scp:*)": "network", "Bash(curl --silent --fail:*)": "network", "Bash(ssh:host.example)": "", "Bash(curl:https://api.example.com/*)": ""} {
		if got := grantRisk(pattern); got != want {
			t.Errorf("%s = %s, want %s", pattern, got, want)
		}
	}
}

func TestRedactionBoundariesAndPaths(t *testing.T) {
	for _, value := range []string{"@modelcontextprotocol/server-github", "task-runner", "AKIA", strings.Repeat("a", 40), "_" + strings.Repeat("a1", 16)} {
		if secret(value, "args") {
			t.Errorf("redacted ordinary value %q", value)
		}
	}
	for _, value := range []string{"sk-test", "AKIA1234567890ABCDEF", strings.Repeat("a1", 16)} {
		if !secret(value, "args") {
			t.Errorf("kept token %q", value)
		}
	}
	r := scanFixture(fixtureHome(t, "home_claude_full"), []AgentLocation{{"claude_code", "~/.claude"}})
	r.Agents[0].MCPServers[0].Source = "/Users/michelosswald/.claude/settings.json"
	r.Agents[0].Skills[0].Name = strings.Repeat("a1", 16)
	r.Credentials[0].Path = "/Users/" + strings.Repeat("a1", 16) + "/.aws/credentials"
	before, _ := r.ContentHash()
	r.finish()
	if r.Hash != before {
		t.Fatal("ordinary paths or names were redacted")
	}
	if got := safeArg("https://example.test/mcp"); got != "https://example.test" {
		t.Fatal(got)
	}
}

func TestPerFileTimeout(t *testing.T) {
	home := t.TempDir()
	release := make(chan struct{})
	defer close(release)
	r := Report{}
	g := guard{ctx: context.Background(), roots: []string{home}, report: &r, readFile: func(string, string) fileResult { <-release; return fileResult{} }}
	start := time.Now()
	result := g.access(filepath.Join(home, "blocked"), "read")
	if result.err != context.DeadlineExceeded || !r.Truncated || r.Coverage.SkippedFiles != 1 || time.Since(start) > time.Second {
		t.Fatalf("timeout not enforced: %+v %+v", result, r)
	}
}

func TestProjectsAndPluginCountsPreserveCredentials(t *testing.T) {
	home := fixtureHome(t, "home_claude_full")
	projects := map[string]any{}
	for i := 0; i < 40; i++ {
		projects[filepath.Join(home, fmt.Sprintf("project-%02d", i))] = map[string]any{}
	}
	data, _ := json.Marshal(map[string]any{"projects": projects})
	writeFixture(t, home, ".claude.json", string(data))
	for i := 0; i < 100; i++ {
		writeFixture(t, home, fmt.Sprintf(".claude/plugins/cache/team/design/v1/skills/skill-%03d/SKILL.md", i), "skill")
		writeFixture(t, home, fmt.Sprintf(".claude/plugins/cache/team/design/v1/agents/agent-%03d.md", i), "agent")
	}
	r := scanFixture(home, []AgentLocation{{"claude_code", "~/.claude"}})
	if r.Truncated || r.Coverage.SkippedFiles != 8 || len(r.Credentials) != 2 || r.Agents[0].Plugins[0].Skills != 101 || r.Agents[0].Plugins[0].Subagents != 100 {
		t.Fatalf("budget lost facts: %+v", r)
	}
}

func TestURLArgumentsKeepOnlyOrigin(t *testing.T) {
	for _, arg := range []string{
		"https://server.example.com/x/mcp?session=123e4567-e89b-12d3-a456-426614174000",
		"https://server.example.com/private#123e4567-e89b-12d3-a456-426614174000",
	} {
		if got := safeArg(arg); got != "https://server.example.com" {
			t.Fatalf("URL leaked private components: %q", got)
		}
	}
}

func TestPermissionPatternsRedactPaths(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	writeFixture(t, home, ".claude/settings.json", `{"permissions":{"allow":["Bash(python3 /Users/michel/scripts/x.py:*)", "Bash(/usr/bin/python3:*)"]}}`)
	r := scanFixture(home, []AgentLocation{{"claude_code", "~/.claude"}})
	grants := r.Agents[0].Permissions.Allow
	if len(grants) != 2 || grants[0].Pattern != "Bash(python3 <redacted>)" || grants[1].Pattern != "Bash(<redacted>)" || grants[0].Risk != "any_shell" {
		t.Fatalf("unsafe grants: %+v", grants)
	}
}

func TestFinishFailsClosed(t *testing.T) {
	r := Report{SchemaVersion: "ghp_private", Agents: []Agent{{ID: "claude_code"}}}
	r.finish()
	if r.SchemaVersion != "" || len(r.Agents) != 0 || r.Hash != "" {
		t.Fatalf("kept rejected report: %+v", r)
	}
}

func TestSecretFlagsRemovedFromEveryCommandSource(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	writeFixture(t, home, ".claude.json", `{"mcpServers":{"test":{"command":"node","args":["--password","P@ssw0rd123","--AuthToken=secret","--verbose"]}}}`)
	writeFixture(t, home, ".claude/settings.json", `{"permissions":{"allow":["Bash(python --password P@ssw0rd123 --AuthToken=secret:*)"]},"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"node --password P@ssw0rd123 --AuthToken=secret --verbose"}]}]}}`)
	r := scanFixture(home, []AgentLocation{{"claude_code", "~/.claude"}})
	data, _ := json.Marshal(r)
	for _, value := range []string{"P@ssw0rd123", "AuthToken", "--password"} {
		if strings.Contains(string(data), value) {
			t.Fatalf("leaked %q", value)
		}
	}
	a := r.Agents[0]
	if len(a.MCPServers) != 1 || len(a.MCPServers[0].Args) != 1 || a.MCPServers[0].Args[0] != "--verbose" || len(a.Hooks) != 1 || a.Hooks[0].Command != "node --verbose" || len(a.Permissions.Allow) != 1 {
		t.Fatalf("lost non-secret command evidence: %+v", a)
	}
}
