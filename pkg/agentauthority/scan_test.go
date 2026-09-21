package agentauthority

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/pkg/agentauthority/readers"
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
	for _, key := range []string{"CLINE_DATA_DIR", "CLINE_DIR", "OPENCODE_CONFIG_DIR", "CRUSH_GLOBAL_CONFIG", "KIMI_CODE_HOME", "KIMI_SHARE_DIR"} {
		t.Setenv(key, "")
	}
	for _, name := range []string{"home_openclaw", "home_qwen_code", "home_goose", "home_factory_droid", "home_devin_cli", "home_pi", "home_kimi_code", "home_auggie", "home_kilo", "home_crush", "home_junie", "home_grok_build", "home_hermes", "home_cursor", "home_windsurf", "home_gemini", "home_cline", "home_opencode", "home_no_prompt_off", "home_claude_full", "home_codex", "home_desktop", "home_generic", "home_empty", "home_planted_token", "home_symlink_to_root", "home_huge_settings", "home_many_files", "home_malformed_json", "home_malformed_toml"} {
		t.Run(name, func(t *testing.T) {
			home := fixtureHome(t, name)
			agents := []AgentLocation{{"claude_code", "~/.claude"}}
			switch name {
			case "home_openclaw":
				agents = []AgentLocation{{"openclaw", "~/.openclaw"}}
			case "home_qwen_code":
				agents = []AgentLocation{{"qwen_code", "~/.qwen"}}
			case "home_goose":
				agents = []AgentLocation{{"goose", "~/.config/goose"}}
			case "home_factory_droid":
				agents = []AgentLocation{{"factory_droid", "~/.factory"}}
			case "home_devin_cli":
				agents = []AgentLocation{{"devin_cli", "~/.config/devin"}}
			case "home_pi":
				agents = []AgentLocation{{"pi", "~/.pi/agent"}}
			case "home_kimi_code":
				agents = []AgentLocation{{"kimi_code", "~/.kimi-code"}}
			case "home_auggie":
				agents = []AgentLocation{{"auggie", "~/.augment"}}
			case "home_kilo":
				agents = []AgentLocation{{"kilo", "~/.config/kilo"}}
			case "home_crush":
				agents = []AgentLocation{{"crush", "~/.config/crush"}}
			case "home_junie":
				agents = []AgentLocation{{"junie", "~/.junie"}}
			case "home_grok_build":
				agents = []AgentLocation{{"grok_build", "~/.grok"}}
			case "home_hermes":
				agents = []AgentLocation{{"hermes", "~/.hermes"}}
			case "home_cursor":
				createCursorFixture(t, home)
				agents = []AgentLocation{{"cursor", "~/.cursor"}}
			case "home_windsurf":
				agents = []AgentLocation{{"windsurf", "~/.windsurf"}}
			case "home_gemini":
				agents = []AgentLocation{{"gemini_cli", "~/.gemini"}}
			case "home_cline":
				agents = []AgentLocation{{"cline", "~/.cline"}}
			case "home_opencode":
				agents = []AgentLocation{{"opencode", "~/.config/opencode"}}
			case "home_no_prompt_off":
				path := createCursorFixture(t, home)
				if output, err := exec.Command("/usr/bin/sqlite3", path, `UPDATE ItemTable SET value='{"composerState":{"useYoloMode":false}}';`).CombinedOutput(); err != nil {
					t.Fatalf("Cursor off fixture: %s %v", output, err)
				}
				agents = []AgentLocation{{"cursor", "~/.cursor"}, {"windsurf", "~/.windsurf"}, {"gemini_cli", "~/.gemini"}, {"cline", "~/.cline"}, {"opencode", "~/.config/opencode"}}
			case "home_codex", "home_malformed_toml":
				agents = []AgentLocation{{"codex", "~/.codex"}}
			case "home_desktop":
				agents = []AgentLocation{{"claude_cowork", "~/Library/Application Support/Claude/local-agent-mode-sessions"}}
			case "home_generic":
				agents = append([]AgentLocation{{"cursor", "~/.cursor"}, {"amp", "~/.config/amp"}, {"opencode", "~/.config/opencode"}}, []AgentLocation{{"openclaw", "~/.openclaw"}, {"qwen_code", "~/.qwen"}, {"goose", "~/.config/goose"}, {"factory_droid", "~/.factory"}, {"devin_cli", "~/.config/devin"}, {"pi", "~/.pi/agent"}, {"kimi_code", "~/.kimi"}, {"auggie", "~/.augment"}, {"kilo", "~/.config/kilo"}, {"crush", "~/.config/crush"}, {"junie", "~/.junie"}, {"grok_build", "~/.grok"}, {"hermes", "~/.hermes"}}...)
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
			data, err := report.CanonicalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if name == "home_planted_token" && bytes.Contains(data, []byte("ghp_")) {
				t.Fatal("secret escaped")
			}
			if strings.HasPrefix(name, "home_symlink") || name == "home_huge_settings" {
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
	r.Agents[0].Plugins[0].Name = strings.Repeat("a1", 16)
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
	home := fixtureHome(t, "home_empty")
	writeFixture(t, home, "blocked", "data")
	release := make(chan struct{})
	defer close(release)
	r := Report{}
	g := guard{ctx: context.Background(), home: home, roots: []string{home}, report: &r, readFile: func(string, string) fileResult { <-release; return fileResult{} }}
	start := time.Now()
	result := g.access(filepath.Join(home, "blocked"), "read")
	if result.err != context.DeadlineExceeded || r.Truncated || g.opened != 0 || r.Coverage.SkippedFiles != 1 || !slices.Equal(r.Coverage.Errors, []string{"read timeout: ~/blocked"}) || time.Since(start) > 1500*time.Millisecond {
		t.Fatalf("timeout not enforced: %+v %+v", result, r)
	}
}

func TestReadTimeoutPreservesAgentFacts(t *testing.T) {
	home := fixtureHome(t, "home_claude_full")
	blocked := filepath.Join(home, ".config/gh/hosts.yml")
	writeFixture(t, home, ".config/gh/hosts.yml", "blocked")
	writeFixture(t, home, ".claude/settings.json", `{"permissions":{"defaultMode":"auto"},"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"kontext hook"}]}]}}`)
	release := make(chan struct{})
	defer close(release)
	r := Report{SchemaVersion: "authority/v1", Agents: []Agent{{ID: "claude_code"}}}
	g := guard{ctx: context.Background(), home: home, managed: filepath.Join(home, "managed"), roots: []string{home}, report: &r, readFile: func(path, mode string) fileResult {
		if path == blocked {
			<-release
			return fileResult{}
		}
		return readGuarded(context.Background(), path, mode)
	}}
	g.credentials()
	g.claude(&r.Agents[0], filepath.Join(home, ".claude"), readers.ClaudeRoot{}, nil)
	r.finish()
	a := r.Agents[0]
	if r.Truncated || r.Coverage.SkippedFiles != 1 || !slices.Equal(r.Coverage.Errors, []string{"read timeout: ~/.config/gh/hosts.yml"}) || len(a.Plugins) == 0 || a.Permissions.DefaultMode == nil || *a.Permissions.DefaultMode != "auto" {
		t.Fatalf("slow project env lost agent facts: %+v", r)
	}
}

func TestReadTimeoutDiagnosticsRedactPaths(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"ghp_private", strings.Repeat("a1", 16)} {
		r := Report{}
		g := guard{home: home, report: &r}
		g.readError(filepath.Join(home, name, ".env"), "read timeout")
		if !slices.Equal(r.Coverage.Errors, []string{"read timeout: <redacted>"}) {
			t.Fatalf("unsafe diagnostic: %q", r.Coverage.Errors)
		}
	}
}

func TestWholeScanDeadlineStopsReads(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	writeFixture(t, home, "blocked", "data")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	r := Report{}
	g := guard{ctx: ctx, home: home, roots: []string{home}, report: &r, readFile: func(string, string) fileResult { <-release; return fileResult{} }}
	result := g.access(filepath.Join(home, "blocked"), "read")
	if result.err != context.DeadlineExceeded || !r.Truncated || r.Coverage.SkippedFiles != 1 || len(r.Coverage.Errors) != 0 {
		t.Fatalf("whole-scan deadline not enforced: %+v %+v", result, r)
	}
	g.readFile = func(string, string) fileResult { t.Error("read after scan deadline"); return fileResult{} }
	g.read(filepath.Join(home, "later"))
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
	if r.Truncated || r.Coverage.SkippedFiles != 0 || !slices.Equal(r.Coverage.Limits, []string{"claude_code: projects limited to 32"}) || len(r.Coverage.Errors) != 0 || len(r.Credentials) != 2 || len(r.Agents[0].Plugins) != 1 {
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
	if len(a.MCPServers) != 1 || len(a.MCPServers[0].Args) != 1 || a.MCPServers[0].Args[0] != "--verbose" || len(a.Permissions.Allow) != 1 {
		t.Fatalf("lost non-secret command evidence: %+v", a)
	}
}

func realDeveloperHome(t *testing.T) string {
	t.Helper()
	home := fixtureHome(t, "home_real_developer")
	for i := 0; i < 40; i++ {
		writeFixture(t, home, fmt.Sprintf(".claude/skills/skill-%02d/SKILL.md", i), "# Skill\n")
	}
	// Sixteen committed manifests/MCP files plus these assets make 400 cache files.
	for i := 0; i < 384; i++ {
		writeFixture(t, home, fmt.Sprintf(".claude/plugins/cache/local/plugin-%d/v1/assets/file-%03d.txt", i%8, i), "cache asset")
	}
	return home
}

func TestRealDeveloperHome(t *testing.T) {
	home := realDeveloperHome(t)
	agents := []AgentLocation{{"claude_code", "~/.claude"}}
	scanFixture(home, agents) // Warm filesystem caches before measuring the scan.
	start := time.Now()
	r := scanFixture(home, agents)
	elapsed := time.Since(start)
	a := r.Agents[0]
	if len(a.Plugins) != 8 || len(a.MCPServers) != 1 || r.Truncated || r.Coverage.SkippedFiles != 0 || len(r.Coverage.Errors) != 0 || !slices.Equal(r.Coverage.Limits, []string{"claude_code: projects limited to 32"}) {
		t.Fatalf("real developer facts lost: %+v", r)
	}
	if elapsed >= 250*time.Millisecond {
		t.Fatalf("warm scan took %s, want under 250ms", elapsed)
	}
	t.Logf("warm scan: %s; 8 plugins, 1 MCP, no truncation", elapsed)
}

func TestSkillsCannotStarveAgentConfigs(t *testing.T) {
	home := realDeveloperHome(t)
	for i := 0; i < maxFiles+1; i++ {
		writeFixture(t, home, fmt.Sprintf(".claude/skills/bulk-%04d/SKILL.md", i), "# Skill\n")
	}
	writeFixture(t, home, ".codex/config.toml", "sandbox_mode = \"danger-full-access\"\n")
	writeFixture(t, home, ".claude/agents/reviewer.md", "---\ntools: Read\n---\n")
	writeFixture(t, home, ".claude/plugins/cache/local/plugin-7/v1/.mcp.json", `{"mcpServers":{"plugin-server":{"command":"node"}}}`)
	writeFixture(t, home, ".claude/plugins/cache/local/plugin-7/v1/hooks/hooks.json", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo test"}]}]}}`)
	r := scanFixture(home, []AgentLocation{{"claude_code", "~/.claude"}, {"codex", "~/.codex"}})
	if r.Truncated || len(r.Agents[0].Plugins) != 8 || len(r.Agents[0].MCPServers) != 2 || r.Agents[1].Permissions.Codex == nil || *r.Agents[1].Permissions.Codex.SandboxMode != "danger-full-access" {
		t.Fatalf("skills starved higher priority facts: %+v", r)
	}
}

func TestFileBudgetCountsOnlyOpenedFiles(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	writeFixture(t, home, "file", "content")
	r := Report{}
	g := guard{ctx: context.Background(), roots: []string{home}, report: &r}
	for i := 0; i < 3; i++ {
		g.entries(home)
		g.read(filepath.Join(home, "missing"))
	}
	if g.opened != 0 {
		t.Fatalf("directory or missing file spent budget: %d", g.opened)
	}
	for i := 0; i < maxFiles; i++ {
		if string(g.read(filepath.Join(home, "file"))) != "content" {
			t.Fatalf("read %d of %d was denied", i+1, maxFiles)
		}
	}
	if g.opened != maxFiles || r.Truncated || g.read(filepath.Join(home, "file")) != nil || !r.Truncated {
		t.Fatalf("file cap not enforced: opened=%d, report=%+v", g.opened, r)
	}
}

func TestSSHKeysCountAndNewestModification(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	for _, name := range []string{"id_rsa", "id_ed25519", "id_work", "id_rsa.pub"} {
		writeFixture(t, home, ".ssh/"+name, "private content must never be read")
	}
	newest := fixtureTime.Add(time.Hour)
	if err := os.Chtimes(filepath.Join(home, ".ssh/id_work"), newest, newest); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/", filepath.Join(home, ".ssh/id_escape")); err != nil {
		t.Fatal(err)
	}
	r := scanFixture(home, nil)
	if len(r.Credentials) != 1 {
		t.Fatalf("want one SSH credential: %+v", r.Credentials)
	}
	c := r.Credentials[0]
	if c.Kind != "ssh_key" || c.Path != "~/.ssh" || c.Detail != 3 || !c.Present || c.ModifiedAt == nil || *c.ModifiedAt != newest.Format(time.RFC3339) {
		t.Fatalf("wrong SSH aggregate: %+v", c)
	}
}

func TestReadRuleRejectsOutsideRootsAndUserContent(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	for _, root := range []string{"Documents", "Desktop", "Downloads", "Library/Mobile Documents", "Library/CloudStorage"} {
		path := filepath.Join(home, root, "repo/.mcp.json")
		r := Report{}
		g := guard{ctx: context.Background(), home: home, roots: []string{home}, report: &r, readFile: func(string, string) fileResult { t.Fatal("opened user content"); return fileResult{} }}
		if g.read(path) != nil || r.Coverage.SkippedFiles != 1 {
			t.Fatalf("accepted %s", path)
		}
	}
	project := filepath.Join(home, "Documents/repo")
	data, _ := json.Marshal(map[string]any{"projects": map[string]any{project: map[string]any{"enabledMcpjsonServers": []string{"approved"}, "mcpServers": map[string]any{"inline": map[string]any{"command": "ignored"}}}}})
	writeFixture(t, home, ".claude.json", string(data))
	writeFixture(t, home, "Documents/repo/.mcp.json", `{"mcpServers":{"unread":{"command":"node"}}}`)
	writeFixture(t, home, "Documents/repo/.env", "PRIVATE_TOKEN=ignored")
	r := scanFixture(home, []AgentLocation{{"claude_code", "~/.claude"}, {"cursor", "~/outside"}})
	if len(r.Agents[0].MCPServers) != 2 || len(r.Credentials) != 0 || r.Truncated {
		t.Fatalf("project facts: %+v", r)
	}
	for _, server := range r.Agents[0].MCPServers {
		if server.Scope != "project" || server.Project == nil || *server.Project != "repo" || server.Command != nil || server.URLHost != nil {
			t.Fatalf("followed project contents: %+v", server)
		}
	}
}

func TestScanReusesUnchangedParseResults(t *testing.T) {
	home := fixtureHome(t, "home_claude_full")
	cache := map[string]fileResult{}
	run := func() (Report, int) {
		r := scanCached(context.Background(), home, Environment{UID: 501}, []AgentLocation{{"claude_code", "~/.claude"}}, fixtureTime, filepath.Join(home, "managed"), cache, nil)
		opened := 0
		for _, result := range cache {
			if result.opened {
				opened++
			}
		}
		return r, opened
	}
	first, opened := run()
	if opened == 0 {
		t.Fatal("first scan opened no files")
	}
	second, opened := run()
	a, _ := first.CanonicalJSON()
	b, _ := second.CanonicalJSON()
	if opened != 0 || !bytes.Equal(a, b) {
		t.Fatalf("unchanged scan opened %d files or changed report", opened)
	}
	path := filepath.Join(home, ".claude/settings.json")
	if err := os.Chtimes(path, fixtureTime.Add(time.Second), fixtureTime.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, opened = run()
	if opened != 1 {
		t.Fatalf("touch reopened %d files, want 1", opened)
	}
}

func TestCustomConfigDirectoryDoesNotExpandReadAllowlist(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	// Discovery honors CLAUDE_CONFIG_DIR, but the approved authority read rule
	// intentionally does not add that path to its fixed configuration roots.
	writeFixture(t, home, "custom-claude/settings.json", `{"permissions":{"defaultMode":"auto"}}`)
	writeFixture(t, home, "custom-claude/plugins/installed_plugins.json", `{"plugins":{}}`)
	r := scanFixture(home, []AgentLocation{{"claude_code", filepath.Join(home, "custom-claude")}})
	if r.Agents[0].Permissions.DefaultMode != nil || len(r.Agents[0].Plugins) != 0 || r.Coverage.SkippedFiles == 0 || r.Truncated {
		t.Fatalf("custom discovery location expanded the read rule: %+v", r)
	}
}
