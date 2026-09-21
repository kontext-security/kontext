package agentauthority

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func createCursorFixture(t *testing.T, home string) string {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("Cursor's SQLite reader is macOS-only")
	}
	path := filepath.Join(home, "Library/Application Support/Cursor/User/globalStorage/state.vscdb")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	sql, err := os.ReadFile("testdata/home_cursor/cursor.sql")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/usr/bin/sqlite3", path)
	cmd.Stdin = strings.NewReader(string(sql))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %s %v", output, err)
	}
	return path
}

func TestCursorCacheAndUnknown(t *testing.T) {
	home := fixtureHome(t, "home_cursor")
	path := createCursorFixture(t, home)
	scanner := new(Scanner)
	run := func() Report {
		return scanner.Scan(context.Background(), home, Environment{}, []AgentLocation{{"cursor", "~/.cursor"}}, fixtureTime)
	}
	first := run()
	if mode := first.Agents[0].Permissions.DefaultMode; mode == nil || *mode != "auto" {
		t.Fatalf("auto-run: %+v", first)
	}
	if len(first.Coverage.Errors) != 0 {
		t.Fatal(first.Coverage.Errors)
	}
	run()
	if scanner.cache[path].opened {
		t.Fatal("unchanged database reopened")
	}
	for _, value := range []string{"false", "null", `"not-a-bool"`} {
		query := `UPDATE ItemTable SET value='{"composerState":{"useYoloMode":` + value + `}}';`
		if out, err := exec.Command("/usr/bin/sqlite3", path, query).CombinedOutput(); err != nil {
			t.Fatalf("update: %s %v", out, err)
		}
		r := run()
		mode := r.Agents[0].Permissions.DefaultMode
		if value == "false" {
			if mode == nil || *mode != "default" {
				t.Fatalf("off: %+v", r)
			}
		} else if mode != nil || len(r.Coverage.Errors) != 1 {
			t.Fatalf("unknown: %+v", r)
		}
	}
	// A large database is queried, never read as a configuration blob.
	if out, err := exec.Command("/usr/bin/sqlite3", path, `CREATE TABLE unrelated (value BLOB); INSERT INTO unrelated VALUES (zeroblob(2097152));`).CombinedOutput(); err != nil {
		t.Fatalf("grow: %s %v", out, err)
	}
	r := run()
	if r.Coverage.SkippedFiles != 0 || len(r.Coverage.Errors) != 1 {
		t.Fatalf("large database skipped: %+v", r)
	}
	if err := os.WriteFile(path, []byte("not sqlite"), 0600); err != nil {
		t.Fatal(err)
	}
	if r := run(); r.Agents[0].Permissions.DefaultMode != nil || len(r.Coverage.Errors) != 1 {
		t.Fatalf("invalid database: %+v", r)
	}
}

func TestPermissionConfigCacheAndOverrides(t *testing.T) {
	home := fixtureHome(t, "home_empty")
	for _, key := range []string{"CLINE_DATA_DIR", "CLINE_DIR", "OPENCODE_CONFIG_DIR"} {
		t.Setenv(key, "")
	}
	t.Setenv("CLINE_DIR", filepath.Join(home, "cline-root"))
	t.Setenv("CLINE_DATA_DIR", filepath.Join(home, "cline-data"))
	t.Setenv("OPENCODE_CONFIG_DIR", filepath.Join(home, "opencode-config"))
	writeFixture(t, home, "cline-root/data/globalState.json", `{"autoApprovalSettings":{"actions":{"executeAllCommands":false}}}`)
	writeFixture(t, home, "cline-data/globalState.json", `{"autoApprovalSettings":{"actions":{"executeAllCommands":true}}}`)
	writeFixture(t, home, "opencode-config/opencode.json", `{"permission":{"bash":"allow"},"mcp":{"example":{"command":["node"]}}}`)
	writeFixture(t, home, ".gemini/settings.json", `{"general":{"defaultApprovalMode":"auto_edit"},"mcpServers":{"example":{"command":"node"}}}`)
	agents := []AgentLocation{{"cline", "~/.cline"}, {"opencode", "~/.config/opencode"}, {"gemini_cli", "~/.gemini"}}
	scanner := new(Scanner)
	run := func() Report { return scanner.Scan(context.Background(), home, Environment{}, agents, fixtureTime) }
	for i := 0; i < 2; i++ {
		r := run()
		for _, a := range r.Agents {
			if a.Permissions.DefaultMode == nil || *a.Permissions.DefaultMode != "auto" {
				t.Fatalf("lost permission: %+v", a)
			}
		}
		if len(r.Agents[1].MCPServers) != 1 || len(r.Agents[2].MCPServers) != 1 {
			t.Fatal("lost MCP facts")
		}
		for _, cached := range scanner.cache {
			if len(cached.data) != 0 || i == 1 && cached.opened {
				t.Fatal("cached raw content or reread unchanged file")
			}
		}
	}
	t.Setenv("CLINE_DATA_DIR", "")
	r := run()
	if mode := r.Agents[0].Permissions.DefaultMode; mode == nil || *mode != "default" {
		t.Fatal("CLINE_DIR fallback ignored")
	}
	// Changed JSONC overrides JSON; removing the key preserves the JSON setting.
	writeFixture(t, home, "opencode-config/opencode.jsonc", `{"permission":{"bash":"ask"},"mcp":{"example":{"command":["replacement-mcp"]}}}`)
	if mode := run().Agents[1].Permissions.DefaultMode; mode == nil || *mode != "default" {
		t.Fatal("JSONC did not override JSON")
	}
	servers := run().Agents[1].MCPServers
	if len(servers) != 1 || servers[0].Command == nil || *servers[0].Command != "replacement-mcp" {
		t.Fatalf("JSONC did not replace MCP definition: %+v", servers)
	}
	writeFixture(t, home, "opencode-config/opencode.jsonc", `{}`)
	if mode := run().Agents[1].Permissions.DefaultMode; mode == nil || *mode != "auto" {
		t.Fatal("absent JSONC key erased JSON setting")
	}
	// Distinct raw names can share a truncated display name and must not collide.
	nameA, nameB := strings.Repeat("x", 128)+"a", strings.Repeat("x", 128)+"b"
	writeFixture(t, home, "opencode-config/opencode.json", fmt.Sprintf(`{"mcp":{%q:{"command":["old"]},%q:{"command":["keep"]}}}`, nameA, nameB))
	writeFixture(t, home, "opencode-config/opencode.jsonc", fmt.Sprintf(`{"mcp":{%q:{"command":["new"]}}}`, nameA))
	for i := 0; i < 2; i++ {
		servers = run().Agents[1].MCPServers
		commands := map[string]bool{}
		for _, server := range servers {
			if server.Command != nil {
				commands[*server.Command] = true
			}
		}
		if len(servers) != 2 || !commands["keep"] || !commands["new"] {
			t.Fatalf("raw names collided: %+v", servers)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	if !scanner.Scan(ctx, home, Environment{}, agents, fixtureTime).Truncated {
		t.Fatal("deadline ignored")
	}
}

func TestNoPromptAbsentAndCursorReadGuard(t *testing.T) {
	for _, key := range []string{"CLINE_DATA_DIR", "CLINE_DIR", "OPENCODE_CONFIG_DIR"} {
		t.Setenv(key, "")
	}
	home := fixtureHome(t, "home_empty")
	agents := []AgentLocation{{"cursor", "~/.cursor"}, {"windsurf", "~/.windsurf"}, {"gemini_cli", "~/.gemini"}, {"cline", "~/.cline"}, {"opencode", "~/.config/opencode"}}
	r := scanFixture(home, agents)
	for _, a := range r.Agents {
		if a.Permissions.DefaultMode != nil {
			t.Fatal("inferred an absent setting")
		}
	}
	if len(r.Coverage.Errors) != 0 || len(r.Coverage.UnknownFormat) != 0 {
		t.Fatalf("absent config coverage: %+v", r.Coverage)
	}
	path := createCursorFixture(t, home)
	outside := filepath.Join(home, "outside.db")
	if err := os.Rename(path, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	r = scanFixture(home, agents[:1])
	if r.Agents[0].Permissions.DefaultMode != nil || r.Coverage.SkippedFiles != 1 {
		t.Fatalf("followed SQLite symlink: %+v", r)
	}
}

func TestCursorWALInvalidatesCachedMode(t *testing.T) {
	home := fixtureHome(t, "home_cursor")
	path := createCursorFixture(t, home)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/sqlite3", "-init", "/dev/null", path)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { input.Close(); cmd.Wait() }()
	lines := bufio.NewScanner(output)
	execute := func(sql string) {
		t.Helper()
		if _, err := io.WriteString(input, sql+"\n.print ready\n"); err != nil {
			t.Fatal(err)
		}
		for lines.Scan() {
			if lines.Text() == "ready" {
				return
			}
		}
		t.Fatalf("SQLite writer stopped: %v", lines.Err())
	}
	execute("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;")
	scanner := new(Scanner)
	run := func() Report {
		return scanner.Scan(ctx, home, Environment{}, []AgentLocation{{"cursor", "~/.cursor"}}, fixtureTime)
	}
	if mode := run().Agents[0].Permissions.DefaultMode; mode == nil || *mode != "auto" {
		t.Fatal("initial mode missing")
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	execute(`UPDATE ItemTable SET value='{"composerState":{"useYoloMode":false}}';`)
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !sameFileVersion(before, after) {
		t.Fatal("test update changed the main database")
	}
	wal, err := os.Stat(path + "-wal")
	if err != nil || wal.Size() == 0 {
		t.Fatalf("expected a nonempty WAL: %v", err)
	}
	r := run()
	if mode := r.Agents[0].Permissions.DefaultMode; mode == nil || *mode != "default" || len(r.Coverage.Errors) != 0 {
		t.Fatalf("WAL-only update was not read: %+v", r)
	}
	run()
	if scanner.cache[path].opened {
		t.Fatal("unchanged WAL reopened database")
	}
	execute(`BEGIN; UPDATE ItemTable SET value='{"composerState":{"useYoloMode":true}}';`)
	if mode := run().Agents[0].Permissions.DefaultMode; mode == nil || *mode != "default" {
		t.Fatal("read an uncommitted change")
	}
	execute("ROLLBACK;")
	execute("PRAGMA wal_checkpoint(TRUNCATE);")
	r = run()
	if mode := r.Agents[0].Permissions.DefaultMode; mode == nil || *mode != "default" || len(r.Coverage.Errors) != 0 {
		t.Fatalf("checkpointed mode missing: %+v", r)
	}
	// Without readable SHM, a read-only query cannot open this WAL database.
	// The immutable fallback must still return the checkpointed default.
	execute(`UPDATE ItemTable SET value='{"composerState":{"useYoloMode":true}}';`)
	if err := os.Remove(path + "-shm"); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700)
	scanner = new(Scanner)
	r = run()
	if mode := r.Agents[0].Permissions.DefaultMode; mode == nil || *mode != "default" || len(r.Coverage.Errors) != 0 {
		t.Fatalf("immutable fallback failed: %+v", r)
	}
}
