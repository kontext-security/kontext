package mcpconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

// Every active Claude Desktop session rewrites its record, so between two
// hooks many records newer than the caller's change. The lookup must not
// decode their connector lists, or it misses its deadline and the connector
// stays unclassified (ENG-758 F5).
func TestDesktopConnectorIgnoresOtherSessionsRewritingRecords(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Library/Application Support/Claude/claude-code-sessions/acct/org")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const connector = "c2be245b-9fd0-47e8-9a48-80c63e49e3fb"
	const url = "https://dbc.cloud.databricks.com/ai-gateway/mcp-services/system.ai.dbsql"
	own := filepath.Join(dir, "local_own.json")
	write := func(path, head, session, pad string) {
		t.Helper()
		record := `{` + head + `"cliSessionId": "` + session + `", "remoteMcpServersConfig": [` + pad + `{"uuid": "` + connector + `", "name": "Databricks", "url": "` + url + `"}]}`
		if err := os.WriteFile(path, []byte(record), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Decoding 30 newer records of 150k connectors each takes well over the
	// 250 ms deadline; their heads take microseconds.
	pad := strings.Repeat(`{"uuid": "x"},`, 150_000)
	age := func(minutes int) {
		t.Helper()
		at := time.Now().Add(-time.Duration(minutes) * time.Minute)
		if err := os.Chtimes(own, at, at); err != nil {
			t.Fatal(err)
		}
	}
	write(own, "", "session-own", "")
	age(60)
	others := make([]string, 30)
	for i := range others {
		others[i] = filepath.Join(dir, fmt.Sprintf("local_%d.json", i))
		write(others[i], "", fmt.Sprintf("session-%d", i), pad)
	}
	r := &Resolver{Home: home, Managed: filepath.Join(home, "managed-mcp.json")}
	tool := "mcp__" + connector + "__execute_sql"
	if got, _, _ := r.Server("claude", "session-own", "/", tool); got != url {
		t.Fatalf("Server() = %q", got)
	}
	for i, path := range others {
		write(path, "", fmt.Sprintf("session-%d", i), pad+`{},`)
	}
	// The caller's record changed too, before the others.
	write(own, "", "session-own", `{},`)
	age(30)
	if got, _, _ := r.Server("claude", "session-own", "/", tool); got != url {
		t.Fatalf("Server() after other sessions rewrote their records = %q", got)
	}
	// A record whose cliSessionId lies past its head is decoded whole.
	write(own, `"title": "`+strings.Repeat("t", 2*recordHeadBytes)+`", `, "session-own", "")
	age(30)
	if got, _, _ := r.Server("claude", "session-own", "/", tool); got != url {
		t.Fatalf("Server() for a cliSessionId past the head = %q", got)
	}
}
