package agentauthority

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func tempHome(t *testing.T) string {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return home
}

func sourceResult(t *testing.T, r Report, id string) SourceResult {
	t.Helper()
	for _, source := range r.Sources {
		if source.ID == id {
			return source
		}
	}
	t.Fatalf("no result for %s in %+v", id, r.Sources)
	return SourceResult{}
}

func assertSource(t *testing.T, r Report, id, status string, reasons ...string) {
	t.Helper()
	got := sourceResult(t, r, id)
	want := append([]string{}, reasons...)
	if got.Status != status || !slices.Equal(got.Reasons, want) {
		t.Fatalf("%s = %s %v, want %s %v", id, got.Status, got.Reasons, status, want)
	}
	if got.StartedAt == "" || got.FinishedAt == "" {
		t.Fatalf("%s has no times: %+v", id, got)
	}
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 || runtime.GOOS == "windows" {
		t.Skip("needs enforced file modes")
	}
}

func TestAbsentAgentStatesEverySourceAsEmpty(t *testing.T) {
	home := tempHome(t)
	r := scanFixture(home, []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor", Absent: true}, {ID: "claude_code", ConfigPath: "~/.claude", Absent: true}})
	assertSource(t, r, "cursor/mcp", StatusComplete)
	assertSource(t, r, "cursor/permissions", StatusComplete)
	for _, family := range []string{"mcp", "plugins", "connectors", "permissions"} {
		assertSource(t, r, "claude_code/"+family, StatusComplete)
	}
	assertSource(t, r, "host/credentials", StatusComplete)
	if len(r.Agents) != 0 {
		t.Fatalf("absent agents got rows: %+v", r.Agents)
	}
	// Cursor has no plugin reader, so no such result exists.
	for _, source := range r.Sources {
		if source.ID == "cursor/plugins" || source.ID == "cursor/connectors" {
			t.Fatalf("unexpected %s", source.ID)
		}
	}
}

func TestAbsentAgentWithClaimsKeepsItsRow(t *testing.T) {
	home := tempHome(t)
	writeFixture(t, home, ".cursor/mcp.json", `{"mcpServers":{"one":{"command":"npx"}}}`)
	r := scanFixture(home, []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor", Absent: true}})
	if len(r.Agents) != 1 || len(r.Agents[0].MCPServers) != 1 {
		t.Fatalf("agents = %+v", r.Agents)
	}
}

func TestListedAgentWithoutClaimsKeepsItsRow(t *testing.T) {
	r := scanFixture(tempHome(t), []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}})
	if len(r.Agents) != 1 {
		t.Fatalf("agents = %+v", r.Agents)
	}
}

// Failure 15: malformed input and permission denials never read as empty.
func TestUnreadableInputIsNeverComplete(t *testing.T) {
	skipIfRoot(t)
	for _, tt := range []struct {
		name, content, reason string
		mode                  os.FileMode
	}{
		{"malformed", `{"mcpServers":`, ReasonMalformed, 0o600},
		{"permission", `{"mcpServers":{}}`, ReasonPermissionDenied, 0o000},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := tempHome(t)
			writeFixture(t, home, ".cursor/mcp.json", tt.content)
			if err := os.Chmod(filepath.Join(home, ".cursor/mcp.json"), tt.mode); err != nil {
				t.Fatal(err)
			}
			r := scanFixture(home, []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}})
			assertSource(t, r, "cursor/mcp", StatusFailed, tt.reason)
		})
	}
}

func TestSymlinkedConfigIsDeniedNotAbsent(t *testing.T) {
	home := tempHome(t)
	writeFixture(t, home, "elsewhere.json", `{"mcpServers":{}}`)
	if err := os.MkdirAll(filepath.Join(home, ".cursor"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "elsewhere.json"), filepath.Join(home, ".cursor/mcp.json")); err != nil {
		t.Fatal(err)
	}
	r := scanFixture(home, []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}})
	assertSource(t, r, "cursor/mcp", StatusFailed, ReasonPermissionDenied)
}

func TestDeadlineFailsEverySource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	home := tempHome(t)
	r := scan(ctx, home, Environment{}, []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}, {ID: "codex", ConfigPath: "~/.codex", Absent: true}}, fixtureTime, filepath.Join(home, "managed"))
	for _, id := range []string{"host/credentials", "cursor/mcp", "cursor/permissions", "codex/mcp", "codex/permissions"} {
		assertSource(t, r, id, StatusFailed, ReasonDeadline)
	}
	if !r.Truncated {
		t.Fatal("report not truncated")
	}
}

// Failure 16: a later good read in the same scan cannot clear the failure.
func TestFailureIsLatchedForTheScan(t *testing.T) {
	home := tempHome(t)
	writeFixture(t, home, ".claude/settings.json", `{`)
	writeFixture(t, home, ".claude/settings.local.json", `{"permissions":{"defaultMode":"plan"}}`)
	r := scanFixture(home, []AgentLocation{{ID: "claude_code", ConfigPath: "~/.claude"}})
	assertSource(t, r, "claude_code/permissions", StatusPartial, ReasonMalformed)
	if r.Agents[0].Permissions.DefaultMode == nil {
		t.Fatal("later read lost")
	}
}

func TestHealthIsPerScan(t *testing.T) {
	home := tempHome(t)
	writeFixture(t, home, ".cursor/mcp.json", `{`)
	scanner := new(Scanner)
	locations := []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}}
	assertSource(t, scanner.Scan(context.Background(), home, Environment{}, locations, fixtureTime), "cursor/mcp", StatusFailed, ReasonMalformed)
	assertSource(t, scanner.Scan(context.Background(), home, Environment{}, locations, fixtureTime), "cursor/mcp", StatusFailed, ReasonMalformed)
	writeFixture(t, home, ".cursor/mcp.json", `{"mcpServers":{}}`)
	assertSource(t, scanner.Scan(context.Background(), home, Environment{}, locations, fixtureTime), "cursor/mcp", StatusComplete)
}

func TestOneSourceFailsBesideOneSucceeding(t *testing.T) {
	home := tempHome(t)
	writeFixture(t, home, ".codex/config.toml", `not toml = [`)
	writeFixture(t, home, ".cursor/mcp.json", `{"mcpServers":{"one":{"command":"npx"}}}`)
	r := scanFixture(home, []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}, {ID: "codex", ConfigPath: "~/.codex"}})
	assertSource(t, r, "cursor/mcp", StatusComplete)
	assertSource(t, r, "codex/mcp", StatusFailed, ReasonMalformed)
	assertSource(t, r, "codex/permissions", StatusFailed, ReasonMalformed)
}

func TestFileTooLargeIsPartial(t *testing.T) {
	home := tempHome(t)
	writeFixture(t, home, ".cursor/mcp.json", strings.Repeat(" ", maxFileBytes+1))
	r := scanFixture(home, []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}})
	assertSource(t, r, "cursor/mcp", StatusPartial, ReasonSizeLimit)
}

func TestProjectCapIsPartial(t *testing.T) {
	home := tempHome(t)
	projects := map[string]any{}
	for i := 0; i < 33; i++ {
		projects[fmt.Sprintf("/p/%d", i)] = map[string]any{}
	}
	data, err := json.Marshal(map[string]any{"projects": projects})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, home, ".claude.json", string(data))
	r := scanFixture(home, []AgentLocation{{ID: "claude_code", ConfigPath: "~/.claude"}})
	assertSource(t, r, "claude_code/mcp", StatusPartial, ReasonWalkLimit)
	assertSource(t, r, "claude_code/permissions", StatusComplete)
}

func TestEntryCapIsPartial(t *testing.T) {
	home := tempHome(t)
	for i := 0; i <= maxFiles; i++ {
		if err := os.MkdirAll(filepath.Join(home, fmt.Sprintf(".hermes/plugins/%04d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r := scanFixture(home, []AgentLocation{{ID: "hermes", ConfigPath: "~/.hermes"}})
	assertSource(t, r, "hermes/plugins", StatusPartial, ReasonWalkLimit)
	assertSource(t, r, "hermes/mcp", StatusComplete)
}

func TestFileBudgetIsWalkLimit(t *testing.T) {
	home := tempHome(t)
	var r Report
	r.Coverage.Errors = []string{}
	g := guard{ctx: context.Background(), home: home, roots: []string{home}, report: &r, opened: maxFiles}
	g.use("cursor", "mcp")
	g.access(filepath.Join(home, ".cursor/mcp.json"), "read")
	got := g.sources["cursor/mcp"].Result(time.Now())
	if got.Status != StatusPartial || !slices.Equal(got.Reasons, []string{ReasonWalkLimit}) {
		t.Fatalf("result = %+v", got)
	}
}

func TestServerCapIsPartial(t *testing.T) {
	home := tempHome(t)
	servers := map[string]any{}
	for i := 0; i < 65; i++ {
		servers[fmt.Sprintf("s%02d", i)] = map[string]any{"command": "npx"}
	}
	data, err := json.Marshal(map[string]any{"mcpServers": servers})
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, home, ".cursor/mcp.json", string(data))
	r := scanFixture(home, []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}})
	assertSource(t, r, "cursor/mcp", StatusPartial, ReasonWalkLimit)
}

func TestFileVanishedAfterEnumeration(t *testing.T) {
	home := tempHome(t)
	writeFixture(t, home, "sessions/acct/org/local_1.json", `{}`)
	var r Report
	r.Coverage.Errors = []string{}
	g := guard{ctx: context.Background(), home: home, roots: []string{home}, report: &r}
	g.use("claude_code", "connectors")
	g.readFile = func(path, mode string) fileResult {
		if mode == "read" {
			return fileResult{err: os.ErrNotExist}
		}
		return readGuarded(context.Background(), path, mode)
	}
	a := Agent{ID: "claude_code"}
	g.connectors(&a, filepath.Join(home, "sessions"))
	got := g.sources["claude_code/connectors"].Result(time.Now())
	if got.Status != StatusPartial || !slices.Equal(got.Reasons, []string{ReasonChangedDuringRead}) {
		t.Fatalf("result = %+v", got)
	}
}

func TestCursorUnknownSettingIsUnsupportedFormat(t *testing.T) {
	home := tempHome(t)
	var r Report
	r.Coverage.Errors = []string{}
	g := guard{ctx: context.Background(), home: home, roots: []string{home}, report: &r, cache: map[string]fileResult{}}
	g.use("cursor", "permissions")
	path := filepath.Join(home, "state.vscdb")
	writeFixture(t, home, "state.vscdb", "x")
	g.readFile = func(string, string) fileResult {
		return fileResult{parsed: (*bool)(nil), parseErr: errors.Join(errParse, errUnsupportedFormat)}
	}
	_, _ = readConfig(&g, "cursor", path, parseJSON[*bool], "read")
	got := g.sources["cursor/permissions"].Result(time.Now())
	if !slices.Equal(got.Reasons, []string{ReasonUnsupportedFormat}) {
		t.Fatalf("result = %+v", got)
	}
}

// A result the report trimmed must not read as a complete enumeration.
func TestTrimmedReportLowersOnlyTheTrimmedSource(t *testing.T) {
	home := tempHome(t)
	servers := map[string]any{}
	for i := 0; i < 64; i++ {
		servers[fmt.Sprintf("%s%02d", strings.Repeat("s", 120), i)] = map[string]any{"command": "npx", "args": []string{strings.Repeat("a", 60), strings.Repeat("b", 60), strings.Repeat("c", 60), strings.Repeat("d", 60)}}
	}
	data, err := json.Marshal(map[string]any{"mcpServers": servers})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{".cursor/mcp.json", ".copilot/mcp-config.json", ".kiro/settings/mcp.json"} {
		writeFixture(t, home, path, string(data))
	}
	r := scanFixture(home, []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}, {ID: "copilot_cli", ConfigPath: "~/.copilot"}, {ID: "kiro", ConfigPath: "~/.kiro"}})
	if !r.Truncated {
		t.Fatal("fixture did not exceed the report budget")
	}
	assertSource(t, r, "kiro/mcp", StatusPartial, ReasonSizeLimit)
	assertSource(t, r, "cursor/mcp", StatusComplete)
}

// A report dropped whole by the secret filter says nothing about any source.
func TestBlankedReportFailsEverySource(t *testing.T) {
	r := Report{Sources: []SourceResult{{ID: "cursor/mcp", Status: StatusComplete, Reasons: []string{}}}}
	r.failSources(ReasonReadError)
	if got := r.Sources[0]; got.Status != StatusFailed || !slices.Equal(got.Reasons, []string{ReasonReadError}) {
		t.Fatalf("result = %+v", got)
	}
}

func TestReasonsAreClosedAndCarryNoText(t *testing.T) {
	skipIfRoot(t)
	home := tempHome(t)
	writeFixture(t, home, ".cursor/mcp.json", `{"secret-parser-text`)
	writeFixture(t, home, ".codex/config.toml", "x")
	if err := os.Chmod(filepath.Join(home, ".codex/config.toml"), 0o000); err != nil {
		t.Fatal(err)
	}
	r := scanFixture(home, []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}, {ID: "codex", ConfigPath: "~/.codex"}})
	closed := []string{ReasonPermissionDenied, ReasonMalformed, ReasonDeadline, ReasonWalkLimit, ReasonSizeLimit, ReasonChangedDuringRead, ReasonUnsupportedFormat, ReasonReadError}
	for _, source := range r.Sources {
		for _, reason := range source.Reasons {
			if !slices.Contains(closed, reason) {
				t.Fatalf("%s reason %q", source.ID, reason)
			}
		}
	}
}

func TestSourcesStayOutOfTheAuthorityWire(t *testing.T) {
	r := scanFixture(tempHome(t), []AgentLocation{{ID: "cursor", ConfigPath: "~/.cursor"}})
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sources") {
		t.Fatalf("wire = %s", data)
	}
}
