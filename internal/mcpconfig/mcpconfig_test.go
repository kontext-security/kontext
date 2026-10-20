package mcpconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// A FIFO planted as a project's .mcp.json must not stall the hook.
func TestServerURLSkipsNonRegularFiles(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "app")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(project, ".mcp.json"), 0o644); err != nil {
		t.Fatal(err)
	}
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
	r := &Resolver{Home: home, Managed: filepath.Join(home, "managed-mcp.json")}
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
	r.mu.Lock()
	defer r.mu.Unlock()
	for key := range r.cache {
		if strings.Contains(key, "Documents") {
			t.Errorf("lookup read %s", strings.SplitN(key, "\x00", 2)[0])
		}
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
	r := &Resolver{Home: home}
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
