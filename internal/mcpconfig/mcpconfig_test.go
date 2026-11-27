package mcpconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// testLookupTimeout replaces the 250 ms lookup budget in tests that check
// what a lookup finds, so a slow runner can't fail them on time alone.
const testLookupTimeout = 30 * time.Second

// A FIFO planted as a project's .mcp.json must not stall the hook.
func TestServerURLSkipsNonRegularFiles(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "app")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	testMkfifo(t, filepath.Join(project, ".mcp.json"))
	r := &Resolver{Home: home, Managed: filepath.Join(home, "managed-mcp.json")}
	if got, _, _ := r.Server("claude", "s", project, "mcp__work__search"); got != "" {
		t.Fatalf("ServerURL() = %q", got)
	}
	if _, err := readFile(filepath.Join(project, ".mcp.json"), maxConfigBytes); err == nil {
		t.Fatal("readFile read a FIFO")
	}
}

// On macOS a lookup must not touch a project in a privacy-guarded folder:
// the daemon would ask the user to let kontext into ~/Documents. There the
// server falls back to its name, even when a lower scope defines the same
// name with another URL. The same project outside such a folder resolves.
func TestServerURLSkipsPrivacyGuardedFolders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the macOS privacy-folder guard does not read Windows paths")
	}
	enabled := privacyfolder.Enabled
	privacyfolder.Enabled = true
	t.Cleanup(func() { privacyfolder.Enabled = enabled })
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	home := t.TempDir()
	const url = "https://work.example/mcp"
	guarded, open := filepath.Join(home, "Documents", "app"), filepath.Join(home, "code", "app")
	for _, project := range []string{guarded, open} {
		if err := os.MkdirAll(project, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(project, ".mcp.json"), []byte(`{"mcpServers": {"work": {"type": "http", "url": "`+url+`"}}}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	userConfig := fmt.Sprintf(`{"mcpServers": {"work": {"type": "http", "url": "https://other.example/mcp"}}, "projects": {%q: {"enabledMcpjsonServers": ["work"]}, %q: {"enabledMcpjsonServers": ["work"]}}}`, guarded, open)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(userConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Resolver{Home: home, Managed: filepath.Join(home, "managed-mcp.json"), Timeout: testLookupTimeout}
	if got, _, _ := r.Server("claude", "s", open, "mcp__work__search"); got != url {
		t.Fatalf("Server() outside a guarded folder = %q, want %q", got, url)
	}
	if got, _, _ := r.Server("claude", "s", guarded, "mcp__work__search"); got != "" {
		t.Fatalf("Server() in ~/Documents = %q, want the name fallback", got)
	}
	// A project outside guarded folders whose .mcp.json links into one: the
	// user-scope URL must not stand in for the unreadable project entry.
	linked := filepath.Join(home, "code", "linked")
	if err := os.MkdirAll(linked, 0o755); err != nil {
		t.Fatal(err)
	}
	hermetic.Symlinks(t)
	if err := os.Symlink(filepath.Join(guarded, ".mcp.json"), filepath.Join(linked, ".mcp.json")); err != nil {
		t.Fatal(err)
	}
	userConfig = fmt.Sprintf(`{"mcpServers": {"work": {"type": "http", "url": "https://other.example/mcp"}}, "projects": {%q: {"enabledMcpjsonServers": ["work"]}}}`, linked)
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(userConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := r.Server("claude", "s", linked, "mcp__work__search"); got != "" {
		t.Fatalf("Server() with .mcp.json linked into ~/Documents = %q, want the name fallback", got)
	}
	// A managed config that links into a guarded folder outranks every other
	// scope, so the user-scope URL must not stand in for it either.
	if err := os.Symlink(filepath.Join(guarded, ".mcp.json"), r.Managed); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := r.Server("claude", "s", filepath.Join(home, "elsewhere"), "mcp__work__search"); got != "" {
		t.Fatalf("Server() with managed-mcp.json linked into ~/Documents = %q, want the name fallback", got)
	}
	// A readable managed config still wins when ~/.claude.json links into a
	// guarded folder: managed outranks the scope that cannot be read.
	const managedURL = "https://managed.example/mcp"
	if err := os.Remove(r.Managed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.Managed, []byte(`{"mcpServers": {"work": {"type": "http", "url": "`+managedURL+`"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(home, ".claude.json"), filepath.Join(guarded, "claude.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(guarded, "claude.json"), filepath.Join(home, ".claude.json")); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := r.Server("claude", "s", filepath.Join(home, "elsewhere"), "mcp__work__search"); got != managedURL {
		t.Fatalf("Server() with ~/.claude.json linked into ~/Documents = %q, want the managed %q", got, managedURL)
	}
	if got, _, _ := r.Server("claude", "s", filepath.Join(home, "elsewhere"), "mcp__other__search"); got != "" {
		t.Fatalf("Server() for a server only ~/.claude.json could define = %q, want the name fallback", got)
	}
	// Only the test home's own ~/Documents counts: a temp dir whose path
	// happens to contain "Documents" is not a guarded folder.
	guardedRoots := []string{filepath.Join(home, "Documents")}
	if real, err := filepath.EvalSymlinks(home); err == nil {
		guardedRoots = append(guardedRoots, filepath.Join(real, "Documents"))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key := range r.cache {
		path := strings.SplitN(key, "\x00", 2)[0]
		for _, root := range guardedRoots {
			if path == root || strings.HasPrefix(path, root+string(filepath.Separator)) {
				t.Errorf("lookup read %s", path)
			}
		}
	}
}

// Claude Desktop 3.x keeps Cowork agent session records in <org>/agent/.
func TestDesktopConnectorReadsCoworkAgentRecords(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	home := t.TempDir()
	dir := filepath.Join(home, "Library/Application Support/Claude/local-agent-mode-sessions/acct/org/agent")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const connector = "c2be245b-9fd0-47e8-9a48-80c63e49e3fb"
	const url = "https://dbc.cloud.databricks.com/ai-gateway/mcp-services/system.ai.dbsql"
	record := `{"cliSessionId": "session-agent", "remoteMcpServersConfig": [{"uuid": "` + connector + `", "name": "Databricks", "url": "` + url + `"}]}`
	if err := os.WriteFile(filepath.Join(dir, "local_agent.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := (&Resolver{Home: home}).desktopConnector(home, "session-agent", connector); got != url {
		t.Fatalf("desktopConnector() = %q", got)
	}
	// The Claude Code CLI names the same connector claude_ai_<Name>; the
	// signed-in organization's agent records hold its URL too.
	const account, org = "11111111-2222-4333-8444-555555555555", "66666666-7777-4888-9999-000000000000"
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"oauthAccount": {"accountUuid": "`+account+`", "organizationUuid": "`+org+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	signedIn := filepath.Join(home, "Library/Application Support/Claude/local-agent-mode-sessions", account, org, "agent")
	if err := os.MkdirAll(signedIn, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(signedIn, "local_agent.json"), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, found := (&Resolver{Home: home}).claudeAIConnector(home, normalize("claude.ai Databricks")); !found || got != url {
		t.Fatalf("claudeAIConnector() = %q, %v", got, found)
	}
}

// An agent folder that links into a guarded folder is checked before it is
// listed, so macOS never asks for access on the daemon's behalf.
func TestDesktopRecordsSkipGuardedAgentFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the macOS privacy-folder guard does not read Windows paths")
	}
	enabled := privacyfolder.Enabled
	privacyfolder.Enabled = true
	t.Cleanup(func() { privacyfolder.Enabled = enabled })
	home := t.TempDir()
	guarded := filepath.Join(home, "Documents", "sessions")
	if err := os.MkdirAll(guarded, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(guarded, "local_guarded.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	org := filepath.Join(home, "Library/Application Support/Claude/local-agent-mode-sessions/acct/org")
	if err := os.MkdirAll(org, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(guarded, filepath.Join(org, "agent")); err != nil {
		t.Fatal(err)
	}
	if records := desktopRecords(home, "*/*"); len(records) != 0 {
		t.Fatalf("desktopRecords() read a guarded agent folder: %v", records)
	}
}

// Every active Claude Desktop session rewrites its record, and a record is
// mostly its connector list, so a lookup that decodes other sessions'
// records whole misses its deadline under load and the connector stays
// unclassified (ENG-758 F5). Only the caller's record may be decoded whole.
func TestDesktopConnectorDecodesOnlyTheCallersRecord(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Library/Application Support/Claude/claude-code-sessions/acct/org")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const connector = "c2be245b-9fd0-47e8-9a48-80c63e49e3fb"
	const url = "https://dbc.cloud.databricks.com/ai-gateway/mcp-services/system.ai.dbsql"
	write := func(path, head, session string, modTime time.Time) {
		t.Helper()
		record := `{` + head + `"cliSessionId": "` + session + `", "remoteMcpServersConfig": [{"uuid": "` + connector + `", "name": "Databricks", "url": "` + url + `"}]}`
		if err := os.WriteFile(path, []byte(record), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, modTime, modTime); err != nil {
			t.Fatal(err)
		}
	}
	// The caller's record is the oldest, so a newest-first scan meets the
	// others first.
	own := filepath.Join(dir, "local_own.json")
	write(own, "", "session-own", time.Now().Add(-time.Hour))
	others := make([]string, 3)
	for i := range others {
		others[i] = filepath.Join(dir, fmt.Sprintf("local_%d.json", i))
		write(others[i], "", fmt.Sprintf("session-%d", i), time.Now())
	}
	r := &Resolver{Home: home, Timeout: testLookupTimeout}
	decoded := func(path string) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		_, ok := r.cache[cacheKey[desktopSession](path, maxConfigBytes)]
		return ok
	}
	if got, _, _ := r.desktopConnector(home, "session-own", connector); got != url {
		t.Fatalf("desktopConnector() = %q", got)
	}
	for _, path := range others {
		if decoded(path) {
			t.Fatalf("desktopConnector() decoded another session's record %s", filepath.Base(path))
		}
	}
	// A record whose cliSessionId lies past its head is decoded whole.
	write(own, `"title": "`+strings.Repeat("t", 2*recordHeadBytes)+`", `, "session-own", time.Now().Add(-time.Hour))
	if got, _, _ := r.desktopConnector(home, "session-own", connector); got != url {
		t.Fatalf("desktopConnector() for a cliSessionId past the head = %q", got)
	}
}

// A daemon that shuts down cancels its warm-up, which then reads no further
// record, so the walk of the session records does not outlive the daemon.
func TestWarmStopsOnceItsContextIsDone(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Library/Application Support/Claude/claude-code-sessions/acct/org")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("local_%d.json", i)), []byte(`{"cliSessionId": "session"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r := &Resolver{Home: home, Timeout: testLookupTimeout}
	cached := func() int {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.cache)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Warm(ctx)
	if n := cached(); n != 0 {
		t.Fatalf("Warm() with a done context cached %d files", n)
	}
	// Each record is cached by its head and whole.
	r.Warm(context.Background())
	if n := cached(); n != 4 {
		t.Fatalf("Warm() cached %d files, want 4", n)
	}
}

// Ways an Antigravity lookup can misidentify a server, each pinned below:
//   - a remote server configured with the legacy serverUrl key has no URL
//   - a name containing "__" is cut at its first separator and takes the URL of
//     a different server, so policy judges the wrong one
//   - two configured names that both fit a tool name pick a winner by accident
//   - the global file beats the workspace's
func TestServerForAntigravity(t *testing.T) {
	home := t.TempDir()
	write := func(path, data string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	project := filepath.Join(home, "app")
	write(filepath.Join(home, ".gemini", "config", "mcp_config.json"), `{"mcpServers":{
		"plain":{"url":"https://plain.example/mcp"},
		"legacy":{"serverUrl":"https://legacy.example/mcp"},
		"both":{"url":"https://url-wins.example/mcp","serverUrl":"https://ignored.example/mcp"},
		"local":{"command":"node"},
		"team__prod":{"url":"https://prod.example/mcp"},
		"clash":{"url":"https://clash.example/mcp"},
		"clash__prod":{"url":"https://clash-prod.example/mcp"},
		"shadowed":{"url":"https://global.example/mcp"}
	}}`)
	write(filepath.Join(project, ".agents", "mcp_config.json"), `{"mcpServers":{"shadowed":{"url":"https://workspace.example/mcp"}}}`)
	r := &Resolver{Home: home, Managed: filepath.Join(home, "managed-mcp.json"), Timeout: testLookupTimeout}
	for _, tc := range []struct{ name, tool, want string }{
		{"url", "mcp__plain__search", "https://plain.example/mcp"},
		{"legacy serverUrl", "mcp__legacy__search", "https://legacy.example/mcp"},
		{"url beats serverUrl", "mcp__both__search", "https://url-wins.example/mcp"},
		{"stdio", "mcp__local__search", ""},
		{"not configured", "mcp__absent__search", ""},
		{"name containing a separator", "mcp__team__prod__search", "https://prod.example/mcp"},
		{"a tool under the shorter name", "mcp__clash__search", "https://clash.example/mcp"},
		{"two names fit", "mcp__clash__prod__search", ""},
		{"workspace beats global", "mcp__shadowed__search", "https://workspace.example/mcp"},
	} {
		if got, _, _ := r.Server("antigravity", "s", project, tc.tool); got != tc.want {
			t.Errorf("%s: %s = %q, want %q", tc.name, tc.tool, got, tc.want)
		}
	}
	if got, _, _ := r.Server("antigravity", "s", "", "mcp__shadowed__search"); got != "https://global.example/mcp" {
		t.Errorf("no workspace = %q", got)
	}
}

func TestClaudeAccountID(t *testing.T) {
	const account = "0F8FAD5B-D9CB-469F-A165-70867728950E"
	for name, tc := range map[string]struct {
		config string
		want   string
	}{
		"signed in":          {`{"oauthAccount": {"accountUuid": "` + account + `", "emailAddress": "a@example.com"}}`, strings.ToLower(account)},
		"signed out":         {`{"projects": {}}`, ""},
		"not an account id":  {`{"oauthAccount": {"accountUuid": "someone@example.com"}}`, ""},
		"not json":           {`{"oauthAccount": `, ""},
		"no config file yet": {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("CLAUDE_CONFIG_DIR", "")
			home := t.TempDir()
			if tc.config != "" {
				if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(tc.config), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got := (&Resolver{Timeout: testLookupTimeout}).ClaudeAccountID(home); got != tc.want {
				t.Fatalf("ClaudeAccountID() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClaudeAccountIDFollowsTheConfigFile(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	home := t.TempDir()
	path := filepath.Join(home, ".claude.json")
	write := func(account string, age time.Duration) {
		t.Helper()
		if err := os.WriteFile(path, []byte(`{"oauthAccount": {"accountUuid": "`+account+`"}}`), 0o644); err != nil {
			t.Fatal(err)
		}
		stamp := time.Now().Add(-age)
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	resolver := &Resolver{Timeout: testLookupTimeout}
	write("0f8fad5b-d9cb-469f-a165-70867728950e", time.Hour)
	if got := resolver.ClaudeAccountID(home); got != "0f8fad5b-d9cb-469f-a165-70867728950e" {
		t.Fatalf("first read = %q", got)
	}
	// The user signs in to another account while the daemon runs.
	write("7c9e6679-7425-40de-944b-e07fc1f90ae7", time.Minute)
	if got := resolver.ClaudeAccountID(home); got != "7c9e6679-7425-40de-944b-e07fc1f90ae7" {
		t.Fatalf("after the config changed = %q, want the new account", got)
	}
}

// stallConfig makes every read of the config at path block until release is
// called, the way a file on a stalled mount does. started counts the reads
// that got as far as the file.
func stallConfig(t *testing.T, path string) (started *atomic.Int64, release func()) {
	t.Helper()
	gate := make(chan struct{})
	left := make(chan struct{}, 64)
	started = &atomic.Int64{}
	stat := statConfig
	statConfig = func(name string) (os.FileInfo, error) {
		if name == path {
			started.Add(1)
			<-gate
			defer func() { left <- struct{}{} }()
		}
		return stat(name)
	}
	var once sync.Once
	release = func() { once.Do(func() { close(gate) }) }
	t.Cleanup(func() {
		release()
		// Every stalled read has left before the real stat is put back.
		for range started.Load() {
			<-left
		}
		statConfig = stat
	})
	return started, release
}

func writeClaudeAccount(t *testing.T, path, account string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(`{"oauthAccount": {"accountUuid": "`+account+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The upload loop asks for the account before every batch. A config on a
// stalled mount must not hold the batch back, must not make the endpoint look
// signed out, and must not pile up blocked reads.
func TestClaudeAccountIDDoesNotWaitForAStalledConfig(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	home := t.TempDir()
	path := filepath.Join(home, ".claude.json")
	const account, other = "0f8fad5b-d9cb-469f-a165-70867728950e", "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	writeClaudeAccount(t, path, account)
	resolver := &Resolver{Timeout: testLookupTimeout}
	if got := resolver.ClaudeAccountID(home); got != account {
		t.Fatalf("before the stall = %q, want %q", got, account)
	}

	started, release := stallConfig(t, path)
	resolver.Timeout = 50 * time.Millisecond
	begin := time.Now()
	for i := range maxLookups + 4 {
		if got := resolver.ClaudeAccountID(home); got != account {
			t.Fatalf("read %d of a stalled config = %q, want the last account read, %q", i+1, got, account)
		}
	}
	if waited := time.Since(begin); waited > 10*time.Second {
		t.Fatalf("%d reads of a stalled config took %s", maxLookups+4, waited.Round(time.Millisecond))
	}
	if got := started.Load(); got != maxLookups {
		t.Fatalf("%d reads are blocked on the stalled config, want %d", got, maxLookups)
	}

	// The mount comes back, with another account signed in.
	writeClaudeAccount(t, path, other)
	release()
	resolver.Timeout = testLookupTimeout
	for deadline := time.Now().Add(10 * time.Second); resolver.ClaudeAccountID(home) != other; {
		if time.Now().After(deadline) {
			t.Fatalf("after the stall = %q, want the new account, %q", resolver.ClaudeAccountID(home), other)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// With nothing read before the stall there is no account to report.
func TestClaudeAccountIDIsEmptyWhenTheFirstReadStalls(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	home := t.TempDir()
	path := filepath.Join(home, ".claude.json")
	writeClaudeAccount(t, path, "0f8fad5b-d9cb-469f-a165-70867728950e")
	stallConfig(t, path)
	resolver := &Resolver{Timeout: 50 * time.Millisecond}
	begin := time.Now()
	if got := resolver.ClaudeAccountID(home); got != "" {
		t.Fatalf("ClaudeAccountID() = %q, want empty: the config was never read", got)
	}
	if waited := time.Since(begin); waited > 10*time.Second {
		t.Fatalf("the read of a stalled config took %s", waited.Round(time.Millisecond))
	}
}

// A signed-out config read after a signed-in one reports no account: the last
// account is kept only while the config can't be read.
func TestClaudeAccountIDForgetsAnAccountTheConfigDropped(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	home := t.TempDir()
	path := filepath.Join(home, ".claude.json")
	writeClaudeAccount(t, path, "0f8fad5b-d9cb-469f-a165-70867728950e")
	resolver := &Resolver{Timeout: testLookupTimeout}
	if got := resolver.ClaudeAccountID(home); got == "" {
		t.Fatal("no account read from a signed-in config")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if got := resolver.ClaudeAccountID(home); got != "" {
		t.Fatalf("after the config was removed = %q, want empty", got)
	}
}
