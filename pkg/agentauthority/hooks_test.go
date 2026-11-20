package agentauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// Ways the hook scan can fail, written down before the tests:
//   - a record type or field the cloud doesn't know fails the strict schema;
//   - an unreadable or privacy-guarded file reads as "no hooks";
//   - an id changes with a command argument, or two identical entries share one;
//   - a command that only names kontext counts as Kontext's own;
//   - a secret in a command reaches the summary;
//   - a handler type the scanner doesn't know is dropped;
//   - a symlink or an oversize file is read;
//   - an absent file lowers the source's status;
//   - too many entries are sent, or cut silently;
//   - a scan without the per-Mac key sends weaker ids.

var testHookKey = []byte("0123456789abcdef0123456789abcdef")

type hookHome struct {
	t                   *testing.T
	home, managed, base string
	// mdm stands in for an MDM profile forcing Claude Code's managed tier.
	mdm bool
}

func newHookHome(t *testing.T) *hookHome {
	t.Helper()
	root := t.TempDir()
	h := &hookHome{t: t, home: filepath.Join(root, "home"), managed: filepath.Join(root, "managed")}
	h.base = filepath.Join(h.home, ".claude")
	for _, dir := range []string{h.base, h.managed} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *hookHome) write(path string, value any) string {
	h.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		h.t.Fatal(err)
	}
	data, ok := value.([]byte)
	if !ok {
		var err error
		if data, err = json.Marshal(value); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		h.t.Fatal(err)
	}
	return path
}

func (h *hookHome) scan(own ...string) (HookAgent, SourceResult) {
	h.t.Helper()
	opts := HookScanOptions{Home: h.home, Key: testHookKey, AgentVersion: "2.1.329", Now: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC), managed: h.managed, mdmPolicy: func() bool { return h.mdm }}
	if len(own) > 0 {
		opts.OwnBinary = func(path string) bool { return slices.Contains(own, path) }
	}
	agent, result, err := scanHooks(context.Background(), opts)
	if err != nil {
		h.t.Fatal(err)
	}
	return agent, result
}

func hooksOf(event, matcher string, handlers ...map[string]any) map[string]any {
	group := map[string]any{"hooks": handlers}
	if matcher != "" {
		group["matcher"] = matcher
	}
	return map[string]any{event: []any{group}}
}

func command(line string) map[string]any { return map[string]any{"type": "command", "command": line} }

// installPlugin writes a plugin into Claude's plugin cache and index.
func (h *hookHome) installPlugin(key string, enabled *bool, hooks map[string]any) {
	name, _, _ := strings.Cut(key, "@")
	dir := filepath.Join(h.base, "plugins/cache", name, "1.4.0")
	h.write(filepath.Join(dir, ".claude-plugin/plugin.json"), map[string]any{"name": name, "version": "1.4.0"})
	h.write(filepath.Join(dir, "hooks/hooks.json"), map[string]any{"hooks": hooks})
	h.write(filepath.Join(h.base, "plugins/installed_plugins.json"), map[string]any{"plugins": map[string]any{key: []any{map[string]any{"installPath": dir}}}})
	if enabled != nil {
		settings := map[string]any{}
		if data, err := os.ReadFile(filepath.Join(h.base, "settings.json")); err == nil {
			_ = json.Unmarshal(data, &settings)
		}
		settings["enabledPlugins"] = map[string]any{key: *enabled}
		h.write(filepath.Join(h.base, "settings.json"), settings)
	}
}

func byEvent(agent HookAgent, event string) []HookRecord {
	var out []HookRecord
	for _, r := range agent.Hooks {
		if r.Event == event {
			out = append(out, r)
		}
	}
	return out
}

func scopeOf(agent HookAgent, id string) HookScope {
	for _, s := range agent.Scopes {
		if s.ID == id {
			return s
		}
	}
	return HookScope{}
}

// The shared fixture decodes with unknown fields disallowed and encodes back
// to the same JSON, so Go and the cloud agree on every field.
func TestHookInventoryFixtureMatchesCloudContract(t *testing.T) {
	data, err := os.ReadFile("testdata/hook-inventory-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	// The cloud pins the same digest (hook-inventory.test.ts in packages/shared).
	if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != "c68fdf163251103870930e43508db914c5fc76ebb52aa0852e8903f1df6ecc23" {
		t.Fatalf("fixture digest %x: change it in both repositories together", sum)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var block HookInventory
	if err := decoder.Decode(&block); err != nil {
		t.Fatalf("fixture does not decode strictly: %v", err)
	}
	encoded, err := json.Marshal(block)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	_ = json.Unmarshal(data, &want)
	_ = json.Unmarshal(encoded, &got)
	if !jsonEqual(want, got) {
		t.Fatalf("re-encoded fixture differs:\n%s", encoded)
	}
	if block.Schema != HookInventorySchema || block.IDScheme != HookIDScheme {
		t.Fatalf("schema %q scheme %d", block.Schema, block.IDScheme)
	}
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// ENG-1065's first acceptance example: Kontext's pre-tool hook, a company
// script and a plugin's post-tool hook all appear with event, origin and scope.
func TestScanHooksThreeHooksFromThreeSources(t *testing.T) {
	h := newHookHome(t)
	// An absolute path on every OS: ownership is checked only for one.
	bin := filepath.Join(h.home, "bin", "kontext")
	h.write(filepath.Join(h.managed, "managed-settings.d", "20-kontext.json"), map[string]any{"hooks": hooksOf("PreToolUse", "*", command(agenthooks.ShellQuote(bin)+" hook pre-tool-use"))})
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("PreToolUse", "Bash", command("bash /Users/dana/bin/check-secrets.sh --strict"))})
	enabled := true
	h.installPlugin("formatter@acme-tools", &enabled, hooksOf("PostToolUse", "Edit|Write", map[string]any{"type": "command", "command": "node ${CLAUDE_PLUGIN_ROOT}/format.js", "timeout": 10}))

	agent, result := h.scan(bin)
	if result.ID != "claude_code/hooks" || result.Status != StatusComplete {
		t.Fatalf("result %+v", result)
	}
	if len(agent.Hooks) != 3 {
		t.Fatalf("hooks %+v", agent.Hooks)
	}
	pre := byEvent(agent, "PreToolUse")
	origins := map[string]string{}
	for _, r := range pre {
		origins[*r.Summary] = r.Origin
	}
	if origins["kontext hook pre-tool-use"] != HookOriginKontext || origins["bash <redacted> --strict"] != HookOriginSettings {
		t.Fatalf("origins %v", origins)
	}
	post := byEvent(agent, "PostToolUse")[0]
	if post.Origin != HookOriginPlugin || post.Plugin == nil || post.Plugin.Name != "formatter" || *post.Plugin.Marketplace != "acme-tools" || *post.Plugin.Version != "1.4.0" || *post.TimeoutS != 10 {
		t.Fatalf("plugin hook %+v", post)
	}
	if scopeOf(agent, post.ScopeID).Kind != HookScopePlugin || scopeOf(agent, pre[0].ScopeID).Kind == "" {
		t.Fatalf("scopes %+v", agent.Scopes)
	}
	for _, r := range agent.Hooks {
		if !strings.HasPrefix(r.ID, "hk_") || len(r.ID) != 25 || !strings.HasPrefix(r.ContentFP, "fp_") || r.Match != "anchor" {
			t.Fatalf("identity %+v", r)
		}
	}
	data, _ := json.Marshal(HookInventory{Schema: HookInventorySchema, IDScheme: HookIDScheme, Agents: []HookAgent{agent}})
	if strings.Contains(string(data), "dana") || strings.Contains(string(data), h.home) {
		t.Fatalf("a path left the Mac: %s", data)
	}
}

// A disabled plugin's hook stays visible as disabled (acceptance example 2).
func TestScanHooksDisabledPluginStaysVisible(t *testing.T) {
	h := newHookHome(t)
	off := false
	h.installPlugin("formatter@acme-tools", &off, hooksOf("PostToolUse", "", command("node format.js")))
	agent, _ := h.scan()
	if len(agent.Hooks) != 1 || agent.Hooks[0].Enablement.State != hookDisabled || !slices.Contains(agent.Hooks[0].Enablement.Reasons, HookReasonPluginDisabled) {
		t.Fatalf("%+v", agent.Hooks)
	}
	if agent.Hooks[0].Evidence.InvocationAt != nil {
		t.Fatal("invented runtime proof")
	}
}

// Naming kontext is not ownership: the binary must be the installed one.
func TestScanHooksOwnershipNeedsTheInstalledBinary(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": map[string]any{
		"PreToolUse":  []any{map[string]any{"matcher": "*", "hooks": []any{command("/tmp/evil/kontext hook pre-tool-use")}}},
		"PostToolUse": []any{map[string]any{"hooks": []any{command("echo kontext")}}},
	}})
	agent, _ := h.scan("/usr/local/bin/kontext")
	for _, r := range agent.Hooks {
		if r.Origin == HookOriginKontext {
			t.Fatalf("unverified Kontext claim accepted: %+v", r)
		}
	}
	if pre := byEvent(agent, "PreToolUse")[0]; !pre.ClaimsKontext {
		t.Fatalf("claim not flagged: %+v", pre)
	}
	if post := byEvent(agent, "PostToolUse")[0]; post.ClaimsKontext {
		t.Fatalf("a word is not a claim: %+v", post)
	}
}

func TestScanHooksIdentity(t *testing.T) {
	h := newHookHome(t)
	settings := filepath.Join(h.base, "settings.json")
	h.write(settings, map[string]any{"hooks": hooksOf("PreToolUse", "Bash", command("bash audit.sh --v1"))})
	first, _ := h.scan()
	h.write(settings, map[string]any{"hooks": hooksOf("PreToolUse", "Bash", command("bash audit.sh --v2"))})
	second, _ := h.scan()
	if first.Hooks[0].ID != second.Hooks[0].ID || first.Hooks[0].ContentFP == second.Hooks[0].ContentFP {
		t.Fatalf("argument change: id must stay, fingerprint must move: %+v %+v", first.Hooks[0], second.Hooks[0])
	}
	h.write(settings, map[string]any{"hooks": hooksOf("PreToolUse", "Edit", command("bash audit.sh --v2"))})
	third, _ := h.scan()
	if third.Hooks[0].ID == second.Hooks[0].ID {
		t.Fatal("a matcher change is a remove plus an add")
	}
	// Key order inside a handler is not a change.
	h.write(settings, []byte(`{"hooks":{"PreToolUse":[{"matcher":"Edit","hooks":[{"command":"bash audit.sh --v2","type":"command"}]}]}}`))
	reordered, _ := h.scan()
	if reordered.Hooks[0].ContentFP != third.Hooks[0].ContentFP {
		t.Fatal("key order changed the fingerprint")
	}
	h.write(settings, map[string]any{"hooks": hooksOf("PreToolUse", "Bash", command("bash a.sh"), command("bash b.sh"))})
	twins, _ := h.scan()
	if twins.Hooks[0].ID == twins.Hooks[1].ID || twins.Hooks[0].Match != "positional" || twins.Hooks[1].Match != "positional" {
		t.Fatalf("identical buckets: %+v", twins.Hooks)
	}
}

// Golden vectors fix the derivations, so a refactor can't silently re-key
// every hook in the fleet.
func TestHookIdentityVectors(t *testing.T) {
	key := []byte("vector-key")
	for _, c := range []struct{ got, want string }{
		{scopeID(key, HookScopeUser, "/Users/dana/.claude/settings.json"), "sc_e2frGzDyHHdhtSRZ5PmHOg"},
		{hookID(key, strings.Join([]string{"claude_code", "sc_x", "", "PreToolUse", "Bash", "command", "cmd:bash"}, "\x00"), 0), "hk_jxHmLgFDTtfUf9cGWd0O-A"},
		{contentFP(key, "PreToolUse", "Bash", json.RawMessage(`{"type":"command","command":"bash a.sh"}`)), "fp_Fn9SkBD3Y4qzPdEfAFjBsA"},
	} {
		if c.got != c.want {
			t.Errorf("got %s, want %s", c.got, c.want)
		}
	}
}

func TestScanHooksIncompleteSourcesAreNotEmpty(t *testing.T) {
	h := newHookHome(t)
	// Malformed user settings, an absent drop-in folder and absent plugins.
	h.write(filepath.Join(h.base, "settings.json"), []byte(`{"hooks": [`))
	// A project Claude lists inside a privacy-guarded folder, and one readable.
	guarded := filepath.Join(h.home, "Documents", "secret-project")
	open := filepath.Join(h.home, "src", "app")
	h.write(filepath.Join(open, ".claude", "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command("say done"))})
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{guarded: map[string]any{}, open: map[string]any{"hasTrustDialogAccepted": true}}})
	agent, result := h.scan()
	if result.Status != StatusPartial || !slices.Contains(result.Reasons, ReasonMalformed) || !slices.Contains(result.Reasons, ReasonPermissionDenied) {
		t.Fatalf("result %+v", result)
	}
	kinds := map[string][]HookScope{}
	for _, s := range agent.Scopes {
		kinds[s.Kind] = append(kinds[s.Kind], s)
	}
	if user := kinds[HookScopeUser][0]; user.Status != StatusFailed || !slices.Equal(user.Reasons, []string{ReasonMalformed}) {
		t.Fatalf("user scope %+v", user)
	}
	if managed := kinds[HookScopeManaged][0]; managed.Status != StatusComplete {
		t.Fatalf("an absent managed file is complete and empty: %+v", managed)
	}
	var failed, complete int
	for _, s := range kinds[HookScopeProject] {
		switch {
		case s.Status == StatusFailed && slices.Equal(s.Reasons, []string{ReasonPermissionDenied}):
			failed++
		case s.Status == StatusComplete:
			complete++
		}
	}
	if failed != 1 || complete != 1 || len(byEvent(agent, "Stop")) != 1 {
		t.Fatalf("project scopes %+v hooks %+v", kinds[HookScopeProject], agent.Hooks)
	}
}

func TestScanHooksRefusesSymlinksAndOversizeFiles(t *testing.T) {
	h := newHookHome(t)
	target := h.write(filepath.Join(h.home, "elsewhere.json"), map[string]any{"hooks": hooksOf("Stop", "", command("x"))})
	if err := os.Symlink(target, filepath.Join(h.base, "settings.json")); err != nil {
		t.Fatal(err)
	}
	h.write(filepath.Join(h.managed, "managed-settings.json"), bytes.Repeat([]byte(" "), maxFileBytes+1))
	agent, result := h.scan()
	if len(agent.Hooks) != 0 || result.Status == StatusComplete {
		t.Fatalf("hooks %+v result %+v", agent.Hooks, result)
	}
	for _, s := range agent.Scopes {
		// A refused link fails; an oversize file is partial (size_limit). Either
		// keeps the cloud from withdrawing what the scope held before.
		if (s.Kind == HookScopeUser || s.Kind == HookScopeManaged) && s.Status == StatusComplete {
			t.Fatalf("scope %+v", s)
		}
	}
}

func TestScanHooksRedactsAndKeepsUnknownTypes(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": map[string]any{
		"PreToolUse": []any{map[string]any{"hooks": []any{
			command("curl -H 'Authorization: Bearer abc' --token ghp_abcdefabcdefabcdef https://user:pw@hooks.example.com/x"),
			map[string]any{"type": "http", "url": "https://user:pw@hooks.example.com/path?key=1"},
			map[string]any{"type": "mcp_tool", "server": "audit", "tool": "check"},
			map[string]any{"type": "prompt", "prompt": "Is this safe? token=abc"},
			map[string]any{"type": "future_kind", "x": 1},
		}}},
	}})
	agent, _ := h.scan()
	if len(agent.Hooks) != 5 {
		t.Fatalf("%+v", agent.Hooks)
	}
	data, _ := json.Marshal(agent)
	for _, leaked := range []string{"ghp_", "Bearer", "pw@", "path?key", "Is this safe"} {
		if strings.Contains(string(data), leaked) {
			t.Fatalf("%q reached the report: %s", leaked, data)
		}
	}
	types := []string{}
	for _, r := range agent.Hooks {
		types = append(types, r.Type)
	}
	if !slices.Equal(types, []string{"command", "http", "mcp_tool", "prompt", "unknown"}) {
		t.Fatalf("types %v", types)
	}
	if *agent.Hooks[1].Summary != "https://user:pw@hooks.example.com" && *agent.Hooks[1].Summary != "https://hooks.example.com" {
		t.Fatalf("http summary %q", *agent.Hooks[1].Summary)
	}
	if *agent.Hooks[2].Summary != "audit/check" || agent.Hooks[3].Summary != nil || agent.Hooks[4].Enablement.State != hookUnresolved {
		t.Fatalf("%+v", agent.Hooks[2:])
	}
}

func TestScanHooksCapsRecords(t *testing.T) {
	h := newHookHome(t)
	handlers := make([]map[string]any, MaxHookRecords+5)
	for i := range handlers {
		handlers[i] = command("echo " + strings.Repeat("x", i%7))
	}
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", handlers...)})
	agent, result := h.scan()
	if len(agent.Hooks) != MaxHookRecords || !agent.Truncated || result.Status != StatusPartial || !slices.Contains(result.Reasons, ReasonSizeLimit) {
		t.Fatalf("%d truncated=%v %+v", len(agent.Hooks), agent.Truncated, result)
	}
}

func TestScanHooksNeedsTheKey(t *testing.T) {
	if _, _, err := ScanHooks(context.Background(), HookScanOptions{Home: t.TempDir()}); !errors.Is(err, ErrNoHookKey) {
		t.Fatalf("err %v", err)
	}
}

func TestKontextHookSet(t *testing.T) {
	h := newHookHome(t)
	bin := h.write(filepath.Join(h.home, "bin", "kontext"), []byte("#!/bin/sh\n"))
	// Written the way Kontext installs it, so a Windows path keeps its
	// backslashes.
	call := func(alias string) map[string]any { return command(agenthooks.ShellQuote(bin) + " hook " + alias) }
	project := filepath.Join(h.home, "src", "app")
	h.write(filepath.Join(project, ".claude", "settings.json"), map[string]any{"hooks": hooksOf("SessionStart", "", call("session-start"))})
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{project: map[string]any{}}})
	user := hooksOf("PreToolUse", "*", call("pre-tool-use"))
	// A narrowed matcher runs for some calls only, so it covers nothing.
	user["PostToolUse"] = hooksOf("PostToolUse", "Bash", call("post-tool-use"))["PostToolUse"]
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": user})
	agent, _ := h.scan(bin)
	missing := agent.KontextHooks.MissingEvents
	if agent.KontextHooks.State != "needs_update" || slices.Contains(missing, "PreToolUse") || !slices.Contains(missing, "PostToolUse") || !slices.Contains(missing, "SessionStart") {
		t.Fatalf("%+v", agent.KontextHooks)
	}
	empty := newHookHome(t)
	if agent, _ := empty.scan(); agent.KontextHooks.State != "missing" {
		t.Fatalf("%+v", agent.KontextHooks)
	}
}

// `NAME=value cmd` runs cmd: the assignment, which can hold a secret, is not
// the program and never reaches the summary.
func TestScanHooksSkipsVariableAssignments(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command("AUTH_HEADER='Basic c2VjcmV0' DEBUG=1 curl -s https://hooks.example.com"))})
	agent, _ := h.scan()
	data, _ := json.Marshal(agent)
	if strings.Contains(string(data), "c2VjcmV0") || strings.Contains(string(data), "AUTH_HEADER") {
		t.Fatalf("assignment reached the report: %s", data)
	}
	if summary := *agent.Hooks[0].Summary; !strings.HasPrefix(summary, "curl") {
		t.Fatalf("summary %q", summary)
	}
}

// A project Claude Code cannot read hides switches for that project only.
func TestScanHooksOtherProjectsFailuresStayThere(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command("say done"))})
	guarded := filepath.Join(h.home, "Documents", "secret-project")
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{guarded: map[string]any{}}})
	agent, result := h.scan()
	if result.Status != StatusPartial {
		t.Fatalf("result %+v", result)
	}
	if state := byEvent(agent, "Stop")[0].Enablement.State; state != hookEnabled {
		t.Fatalf("user hook %s", state)
	}
}

func TestScanHooksProjectCapMarksTruncated(t *testing.T) {
	h := newHookHome(t)
	projects := map[string]any{}
	for i := range maxHookProjects + 1 {
		projects[filepath.Join(h.home, "src", fmt.Sprint("p", i))] = map[string]any{}
	}
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": projects})
	agent, result := h.scan()
	if !agent.Truncated || result.Status == StatusComplete || !slices.Contains(result.Reasons, ReasonWalkLimit) {
		t.Fatalf("truncated=%v %+v", agent.Truncated, result)
	}
}

// Every field the shared fixture holds as a list is a list in real scan
// output too, never null: the cloud's strict schema rejects the whole block
// otherwise.
func TestHookScanOutputNeverNullsAList(t *testing.T) {
	data, err := os.ReadFile("testdata/hook-inventory-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture any
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	lists := map[string]bool{}
	var collect func(any)
	collect = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, child := range v {
				if _, ok := child.([]any); ok {
					lists[k] = true
				}
				collect(child)
			}
		case []any:
			for _, child := range v {
				collect(child)
			}
		}
	}
	collect(fixture)

	h := newHookHome(t)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": map[string]any{
		"PreToolUse": []any{map[string]any{"matcher": "Bash", "hooks": []any{command("bash a.sh"), command("/no/such/tool")}}},
		"Stop":       []any{map[string]any{"hooks": []any{map[string]any{"type": "http", "url": "https://hooks.example.com/x"}}}},
	}})
	agent, _ := h.scan()
	encoded, _ := json.Marshal(HookInventory{Schema: HookInventorySchema, IDScheme: HookIDScheme, Agents: []HookAgent{agent}})
	var out any
	if err := json.Unmarshal(encoded, &out); err != nil {
		t.Fatal(err)
	}
	var check func(string, any)
	check = func(path string, v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, child := range v {
				if child == nil && lists[k] {
					t.Errorf("%s.%s is null", path, k)
				}
				check(path+"."+k, child)
			}
		case []any:
			for i, child := range v {
				check(fmt.Sprintf("%s[%d]", path, i), child)
			}
		}
	}
	check("", out)
	if len(lists) < 4 {
		t.Fatalf("fixture lists %v", lists)
	}
}

// A credential can sit in any argument, not only behind a flag the scanner
// knows: summaries keep plain words and flag names, nothing else.
func TestHookSummaryKeepsOnlySafeWords(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": map[string]any{
		"Stop":       []any{map[string]any{"hooks": []any{command("curl -u alice:example-password https://bob:pw@hooks.example.test/x?token=abc")}}},
		"PreToolUse": []any{map[string]any{"matcher": "Bash|/Users/dana/private/tool", "hooks": []any{command("deploy-check --password hunter2 --mode=strict run")}}},
	}})
	agent, _ := h.scan()
	data, _ := json.Marshal(agent)
	for _, leaked := range []string{"alice", "example-password", "bob", "hunter2", "strict", "token", "/Users/dana"} {
		if strings.Contains(string(data), leaked) {
			t.Fatalf("%q reached the report: %s", leaked, data)
		}
	}
	if got := *byEvent(agent, "Stop")[0].Summary; got != "curl -u <redacted>" {
		t.Fatalf("stop summary %q", got)
	}
	pre := byEvent(agent, "PreToolUse")[0]
	if got := *pre.Summary; got != "deploy-check --password <redacted> --mode <redacted>" {
		t.Fatalf("pre summary %q", got)
	}
	if *pre.Matcher != "Bash|<redacted>" {
		t.Fatalf("matcher %q", *pre.Matcher)
	}
}

// The privacy guard sees through another spelling of a guarded folder, and
// verifying a Kontext binary never touches one.
func TestHookScanRespectsPrivacyFoldersBySpelling(t *testing.T) {
	previous := privacyfolder.Enabled
	privacyfolder.Enabled = true
	t.Cleanup(func() { privacyfolder.Enabled = previous })
	h := newHookHome(t)
	project := filepath.Join(h.home, "documents", "repo")
	h.write(filepath.Join(project, ".claude", "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command("say done"))})
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{project: map[string]any{}}})
	guardedBin := filepath.Join(h.home, "Documents", "tools", "kontext")
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("PreToolUse", "", command(guardedBin+" hook pre-tool-use"))})
	opts := HookScanOptions{Home: h.home, Key: testHookKey, Now: time.Now(), managed: h.managed, mdmPolicy: func() bool { return false },
		OwnBinary: func(path string) bool { t.Fatalf("verified %s inside a guarded folder", path); return false }}
	agent, result, err := scanHooks(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(byEvent(agent, "Stop")) != 0 || result.Status == StatusComplete || !slices.Contains(result.Reasons, ReasonPermissionDenied) {
		t.Fatalf("guarded project read: %+v %+v", agent.Hooks, result)
	}
}

// One plugin installed twice is two scopes with distinct ids, or one scope
// when the same install is listed twice; hooks from hooks/hooks.json and
// from the manifest (a file list and an inline object) all load.
func TestPluginScopesAreUniqueAndLoadEveryDeclaration(t *testing.T) {
	h := newHookHome(t)
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	h.write(filepath.Join(dir, ".claude-plugin/plugin.json"), map[string]any{"name": "formatter", "version": "1.4.0",
		"hooks": []any{"./extra/more.json", map[string]any{"SessionEnd": []any{map[string]any{"hooks": []any{command("echo bye")}}}}}})
	h.write(filepath.Join(dir, "hooks/hooks.json"), map[string]any{"hooks": hooksOf("Stop", "", command("echo stop"))})
	h.write(filepath.Join(dir, "extra/more.json"), map[string]any{"hooks": hooksOf("PreToolUse", "Edit", command("echo pre"))})
	install := map[string]any{"installPath": dir}
	project := map[string]any{"installPath": dir, "projectPath": filepath.Join(h.home, "src", "app")}
	h.write(filepath.Join(h.base, "plugins/installed_plugins.json"), map[string]any{"plugins": map[string]any{"formatter@acme": []any{install, install, project}}})
	agent, _ := h.scan()
	ids := map[string]bool{}
	for _, scope := range agent.Scopes {
		if ids[scope.ID] {
			t.Fatalf("duplicate scope %s", scope.ID)
		}
		ids[scope.ID] = true
	}
	plugins := 0
	for _, scope := range agent.Scopes {
		if scope.Kind == HookScopePlugin {
			plugins++
		}
	}
	if plugins != 2 {
		t.Fatalf("%d plugin scopes", plugins)
	}
	for _, event := range []string{"Stop", "PreToolUse", "SessionEnd"} {
		if got := len(byEvent(agent, event)); got != 2 {
			t.Fatalf("%s: %d hooks", event, got)
		}
	}
}

// Kontext's set counts only handlers that run for every call everywhere: not
// a project's, not one narrowed by a matcher the summary hides, not one with
// a handler-level if, and not a managed file an MDM profile replaces.
func TestKontextHookSetNeedsDeviceWideUnconditionalHandlers(t *testing.T) {
	setup := func(t *testing.T) (*hookHome, string, func(string) map[string]any) {
		h := newHookHome(t)
		bin := h.write(filepath.Join(h.home, "bin", "kontext"), []byte("#!/bin/sh\n"))
		call := func(alias string) map[string]any { return command(agenthooks.ShellQuote(bin) + " hook " + alias) }
		return h, bin, call
	}
	all := func(call func(string) map[string]any, matcher string, extra map[string]any) map[string]any {
		hooks := map[string]any{}
		for _, event := range claudemanaged.SupportedEvents {
			handler := call(event.Alias)
			for k, v := range extra {
				handler[k] = v
			}
			hooks[event.Name.String()] = hooksOf(event.Name.String(), matcher, handler)[event.Name.String()]
		}
		return hooks
	}
	t.Run("user settings complete", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": all(call, "", nil)})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != "complete" {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("trusted project only", func(t *testing.T) {
		h, bin, call := setup(t)
		project := filepath.Join(h.home, "src", "app")
		h.write(filepath.Join(project, ".claude", "settings.json"), map[string]any{"hooks": all(call, "", nil)})
		h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{project: map[string]any{"hasTrustDialogAccepted": true}}})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != "missing" {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("matcher hidden from the summary", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": all(call, "/opt/tool", nil)})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != "missing" {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("handler-level if", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": all(call, "*", map[string]any{"if": "Bash(git *)"})})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != "missing" {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("async handler", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": all(call, "", map[string]any{"async": true})})
		// Only the events Kontext installs to run in the background stay
		// covered: a background PreToolUse can't block.
		agent, _ := h.scan(bin)
		if agent.KontextHooks.State != "needs_update" || !slices.Equal(agent.KontextHooks.MissingEvents, []string{"PreToolUse", "PostToolUse", "PostToolUseFailure", "UserPromptSubmit"}) {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("the installer's own shape", func(t *testing.T) {
		h, bin, _ := setup(t)
		settings := claudemanaged.Template(bin)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": settings.Hooks})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != "complete" {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("asyncRewake runs in the background", func(t *testing.T) {
		h, bin, call := setup(t)
		hooks := all(call, "", nil)
		hooks["PreToolUse"] = hooksOf("PreToolUse", "", func() map[string]any {
			handler := call("pre-tool-use")
			handler["asyncRewake"] = true
			return handler
		}())["PreToolUse"]
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooks})
		if agent, _ := h.scan(bin); !slices.Equal(agent.KontextHooks.MissingEvents, []string{"PreToolUse"}) {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("a local project file turns the shared switch back on", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": all(call, "", nil)})
		project := filepath.Join(h.home, "src", "app")
		h.write(filepath.Join(project, ".claude", "settings.json"), map[string]any{"disableAllHooks": true})
		h.write(filepath.Join(project, ".claude", "settings.local.json"), map[string]any{"disableAllHooks": false})
		h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{project: map[string]any{"hasTrustDialogAccepted": true}}})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != "complete" {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("an unread project can't prove the set", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": all(call, "", nil)})
		projects := map[string]any{}
		for i := range maxHookProjects + 1 {
			projects[filepath.Join(h.home, "src", fmt.Sprintf("app%02d", i))] = map[string]any{}
		}
		h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": projects})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != KontextHooksUnknown {
			t.Fatalf("%+v", agent.KontextHooks)
		}
		// Proven coverage still reads as complete without the user's
		// handlers: managed ones run in every project.
		h.write(filepath.Join(h.managed, "managed-settings.d", "20-kontext.json"), map[string]any{"hooks": all(call, "", nil)})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != "complete" {
			t.Fatalf("managed %+v", agent.KontextHooks)
		}
	})
	t.Run("a project turns user hooks off", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": all(call, "", nil)})
		project := filepath.Join(h.home, "src", "app")
		h.write(filepath.Join(project, ".claude", "settings.json"), map[string]any{"disableAllHooks": true})
		h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{project: map[string]any{"hasTrustDialogAccepted": true}}})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != "missing" {
			t.Fatalf("%+v", agent.KontextHooks)
		}
		// Managed handlers keep running there.
		h.write(filepath.Join(h.managed, "managed-settings.d", "20-kontext.json"), map[string]any{"hooks": all(call, "", nil)})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != "complete" {
			t.Fatalf("managed %+v", agent.KontextHooks)
		}
	})
	t.Run("managed file shadowed by MDM", func(t *testing.T) {
		h, bin, call := setup(t)
		h.mdm = true
		h.write(filepath.Join(h.managed, "managed-settings.d", "20-kontext.json"), map[string]any{"hooks": all(call, "", nil)})
		// The profile may still run them: unknown, never missing.
		agent, _ := h.scan(bin)
		if agent.KontextHooks.State != KontextHooksUnknown {
			t.Fatalf("%+v", agent.KontextHooks)
		}
		if r := agent.Hooks[0]; r.Enablement.State != hookUnresolved || !slices.Contains(r.Enablement.Reasons, HookReasonManagedTierShadowed) {
			t.Fatalf("%+v", r.Enablement)
		}
	})
	t.Run("a managed file past the scope cap can't prove the set", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.managed, "managed-settings.json"), map[string]any{"hooks": all(call, "", nil)})
		for i := range MaxHookScopes {
			h.write(filepath.Join(h.managed, "managed-settings.d", fmt.Sprintf("%03d.json", i)), map[string]any{})
		}
		agent, _ := h.scan(bin)
		if agent.KontextHooks.State != KontextHooksUnknown {
			t.Fatalf("%+v", agent.KontextHooks)
		}
		// The unread file could disable every hook, so none reads as enabled.
		for _, r := range agent.Hooks {
			if r.Enablement.State != hookUnresolved || r.Evidence.ConfigCheckedAt != nil {
				t.Fatalf("%+v %+v", r.Enablement, r.Evidence)
			}
		}
		if len(agent.Hooks) == 0 {
			t.Fatal("no hooks")
		}
	})
	t.Run("a later managed file adds to plugin-only customization", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": all(call, "", nil)})
		h.write(filepath.Join(h.managed, "managed-settings.json"), map[string]any{"strictPluginOnlyCustomization": []string{"hooks"}})
		h.write(filepath.Join(h.managed, "managed-settings.d", "20-skills.json"), map[string]any{"strictPluginOnlyCustomization": []string{"skills"}})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != "missing" {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("a switch of the wrong type leaves the set unknown", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": all(call, "", nil)})
		h.write(filepath.Join(h.managed, "managed-settings.json"), map[string]any{"allowManagedHooksOnly": "true"})
		if agent, _ := h.scan(bin); agent.KontextHooks.State != KontextHooksUnknown {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("keys in another case are not Claude's", func(t *testing.T) {
		h, bin, _ := setup(t)
		hooks := map[string]any{}
		for _, event := range claudemanaged.SupportedEvents {
			hooks[event.Name.String()] = []any{map[string]any{"hooks": []any{map[string]any{"Type": "command", "Command": agenthooks.ShellQuote(bin) + " hook " + event.Alias}}}}
		}
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooks})
		if agent, _ := h.scan(bin); agent.KontextHooks.State == "complete" {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("an MDM profile with no handler on disk is unknown, not missing", func(t *testing.T) {
		h, bin, _ := setup(t)
		h.mdm = true
		if agent, _ := h.scan(bin); agent.KontextHooks.State != KontextHooksUnknown {
			t.Fatalf("%+v", agent.KontextHooks)
		}
	})
	t.Run("an unreadable project list can't prove the set", func(t *testing.T) {
		h, bin, call := setup(t)
		h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": all(call, "", nil)})
		h.write(filepath.Join(h.home, ".claude.json"), []byte("{"))
		agent, result := h.scan(bin)
		if agent.KontextHooks.State != KontextHooksUnknown {
			t.Fatalf("%+v", agent.KontextHooks)
		}
		// Its projects went unseen, so the cloud withdraws none of them.
		if result.Status == StatusComplete || !slices.Contains(result.Reasons, ReasonMalformed) {
			t.Fatalf("%+v", result)
		}
	})
}

// An ownership check on a stalled filesystem can't hold the scan: the hook
// stays unverified.
func TestStalledOwnershipCheckLeavesTheHookUnverified(t *testing.T) {
	h := newHookHome(t)
	bin := h.write(filepath.Join(h.home, "bin", "kontext"), []byte("#!/bin/sh\n"))
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("PreToolUse", "", command(agenthooks.ShellQuote(bin)+" hook pre-tool-use"))})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	opts := HookScanOptions{Home: h.home, Key: testHookKey, Now: time.Now(), managed: h.managed, mdmPolicy: func() bool { return false },
		OwnBinary: func(string) bool { <-release; return true }}
	start := time.Now()
	agent, _, err := scanHooks(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 5*programStatTimeout {
		t.Fatalf("scan waited %v on a stalled check", elapsed)
	}
	if len(agent.Hooks) != 1 || agent.Hooks[0].Origin == HookOriginKontext {
		t.Fatalf("%+v", agent.Hooks)
	}
	// Unverified is not "not Kontext's": the set can't be called incomplete.
	if agent.KontextHooks.State != KontextHooksUnknown {
		t.Fatalf("%+v", agent.KontextHooks)
	}
}

// A null project or plugin registry is no registry: read as empty, it would
// withdraw every project and plugin hook it lists.
func TestNullRegistriesAreNotEmpty(t *testing.T) {
	for _, file := range []string{".claude.json", "plugins/installed_plugins.json"} {
		t.Run(file, func(t *testing.T) {
			h := newHookHome(t)
			path := filepath.Join(h.base, file)
			if file == ".claude.json" {
				path = filepath.Join(h.home, file)
			}
			h.write(path, []byte("null"))
			if _, result := h.scan(); result.Status == StatusComplete || !slices.Contains(result.Reasons, ReasonMalformed) {
				t.Fatalf("%+v", result)
			}
		})
	}
}

// Only the behavior key's value is decoded, so a profile whose entries share
// one large string can't expand past its own size; a control-only profile is
// no policy.
func TestMDMProfileDecodingIsBounded(t *testing.T) {
	if entries, ok := binaryPlistTopEntries(binaryPlistStrings("hooks", strings.Repeat("x", 200))); !ok || entries[0].key != "hooks" || entries[0].str != nil {
		t.Fatalf("%v %+v", ok, entries)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "control.plist")
	if err := os.WriteFile(path, binaryPlistStrings("wslInheritsWindowsSettings", "x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if mode := mdmPlistMode(path); mode != mdmNone {
		t.Fatalf("control-only profile = %v", mode)
	}
}

// enabledPlugins follows Claude Code's precedence: managed settings win over
// the user's, and a project's own settings decide for a plugin installed for
// that project.
func TestPluginEnablementPrecedence(t *testing.T) {
	h := newHookHome(t)
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	h.write(filepath.Join(dir, "hooks/hooks.json"), map[string]any{"hooks": hooksOf("Stop", "", command("echo stop"))})
	other := filepath.Join(h.base, "plugins/cache", "linter", "2.0.0")
	h.write(filepath.Join(other, "hooks/hooks.json"), map[string]any{"hooks": hooksOf("PreToolUse", "", command("echo lint"))})
	project := filepath.Join(h.home, "src", "app")
	h.write(filepath.Join(h.base, "plugins/installed_plugins.json"), map[string]any{"plugins": map[string]any{
		"formatter@acme": []any{map[string]any{"installPath": dir}},
		"linter@acme":    []any{map[string]any{"installPath": other, "projectPath": project}},
	}})
	h.write(filepath.Join(h.managed, "managed-settings.json"), map[string]any{"enabledPlugins": map[string]any{"formatter@acme": false}})
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"enabledPlugins": map[string]any{"formatter@acme": true, "linter@acme": true}})
	h.write(filepath.Join(project, ".claude", "settings.json"), map[string]any{"enabledPlugins": map[string]any{"linter@acme": false}})
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{project: map[string]any{"hasTrustDialogAccepted": true}}})
	agent, _ := h.scan()
	for _, event := range []string{"Stop", "PreToolUse"} {
		r := byEvent(agent, event)[0]
		if r.Enablement.State != hookDisabled || !slices.Contains(r.Enablement.Reasons, HookReasonPluginDisabled) {
			t.Fatalf("%s: %+v", event, r.Enablement)
		}
	}
}

// "args": [] is exec form: Claude Code runs the whole command string as the
// executable's name, so it is never Kontext's call.
func TestEmptyArgsIsExecForm(t *testing.T) {
	h := newHookHome(t)
	bin := h.write(filepath.Join(h.home, "bin", "kontext"), []byte("#!/bin/sh\n"))
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("PreToolUse", "", map[string]any{"type": "command", "command": bin + " hook pre-tool-use", "args": []any{}})})
	agent, _ := h.scan(bin)
	if r := agent.Hooks[0]; r.Origin == HookOriginKontext {
		t.Fatalf("empty args verified as Kontext's call: %+v", r)
	}
}

// With CLAUDE_CONFIG_DIR, Claude Code reads that profile's settings,
// plugins and .claude.json, never the default profile's.
func TestScanHooksReadsTheActiveProfile(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command("personal.sh"))})
	work := filepath.Join(h.home, "profiles", "work")
	h.write(filepath.Join(work, "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command("work.sh"))})
	project := filepath.Join(h.home, "src", "work-app")
	h.write(filepath.Join(project, ".claude", "settings.json"), map[string]any{"hooks": hooksOf("SessionEnd", "", command("project.sh"))})
	h.write(filepath.Join(work, ".claude.json"), map[string]any{"projects": map[string]any{project: map[string]any{}}})
	agent, _, err := scanHooks(context.Background(), HookScanOptions{Home: h.home, ConfigDir: work, Key: testHookKey, Now: time.Now(), managed: h.managed, mdmPolicy: func() bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	summaries := []string{}
	for _, r := range agent.Hooks {
		summaries = append(summaries, *r.Summary)
	}
	slices.Sort(summaries)
	if !slices.Equal(summaries, []string{"project.sh", "work.sh"}) {
		t.Fatalf("summaries %v", summaries)
	}
}

// A positional word can be a password, so only an interpreter's script
// stays readable: a script suffix elsewhere proves nothing.
func TestHookSummaryDropsPositionalWords(t *testing.T) {
	for _, c := range []struct{ program, args, want string }{
		{"/usr/bin/redis-cli", "AUTH hunter2", "redis-cli <redacted>"},
		{"/usr/bin/redis-cli", "AUTH winterblue.sh", "redis-cli <redacted>"},
		{"/usr/bin/redis-cli", "check-secrets.sh --strict", "redis-cli <redacted> --strict"},
		{"/usr/bin/redis-cli", "--verbose", "redis-cli --verbose"},
		{"bash", "check-secrets.sh --strict", "bash check-secrets.sh --strict"},
		{"bash", "-e check.sh", "bash -e <redacted>"},
		{"python3", "run.py Winter2026.py", "python3 run.py <redacted>"},
		{"node", "--token x format.js", "node --token <redacted>"},
		// A flag can take the script's place: what follows is data.
		{"python3", "-m audit Winter2026.py", "python3 -m <redacted>"},
		{"python", "-c code winter.py", "python -c <redacted>"},
		{"bash", "check.sh", "bash check.sh"},
		{"/opt/hooks/check.sh", "spring.sh", "check.sh <redacted>"},
	} {
		if got := hookSummary(c.program, strings.Fields(c.args)); got != c.want {
			t.Errorf("hookSummary(%q, %q) = %q, want %q", c.program, c.args, got, c.want)
		}
	}
}

// Hook fields use the cloud's token class, where _ and - join a token.
func TestHookSecretMatchesTheCloudsTokens(t *testing.T) {
	for _, value := range []string{"npm_" + strings.Repeat("a1", 16), "Stop_" + strings.Repeat("x9", 16), "abc_def-0123456789abcdefghijklmnopqrstuv"} {
		if !hookSecret(value) {
			t.Errorf("%q not flagged", value)
		}
	}
	for _, value := range []string{"PreToolUse", "check-secrets.sh", strings.Repeat("a", 40)} {
		if hookSecret(value) {
			t.Errorf("%q flagged", value)
		}
	}
}

// Fields are cut to the cloud's UTF-16 length, at a whole rune.
func TestSafeCountsUTF16Units(t *testing.T) {
	value := strings.Repeat("\U0001F600", 130)
	got := safe(value, 256)
	if n := len(utf16.Encode([]rune(got))); n != 256 || !utf8.ValidString(got) {
		t.Fatalf("cut to %d units, valid=%v", n, utf8.ValidString(got))
	}
	if safe("abc", 256) != "abc" {
		t.Fatal("short value changed")
	}
}

// A plugin installed for a project runs under that project's settings.
func TestProjectPluginFollowsItsProjectsSwitches(t *testing.T) {
	h := newHookHome(t)
	project := filepath.Join(h.home, "src", "app")
	h.write(filepath.Join(project, ".claude", "settings.json"), map[string]any{"disableAllHooks": true})
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{project: map[string]any{"hasTrustDialogAccepted": true}}})
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	h.write(filepath.Join(dir, "hooks/hooks.json"), map[string]any{"hooks": hooksOf("Stop", "", command("echo stop"))})
	h.write(filepath.Join(h.base, "plugins/installed_plugins.json"), map[string]any{"plugins": map[string]any{
		"formatter@acme": []any{map[string]any{"installPath": dir, "scope": "project", "projectPath": project}},
	}})
	agent, _ := h.scan()
	if len(agent.Hooks) != 1 {
		t.Fatalf("hooks %+v", agent.Hooks)
	}
	if r := agent.Hooks[0]; r.Enablement.State != "disabled" || !slices.Contains(r.Enablement.Reasons, HookReasonDisableAllHooks) {
		t.Fatalf("%+v", r.Enablement)
	}
}

// Managed files an MDM profile replaced don't switch other hooks off, but the
// unreadable profile leaves them unresolved.
func TestShadowedManagedFilesDoNotDisable(t *testing.T) {
	h := newHookHome(t)
	h.mdm = true
	h.write(filepath.Join(h.managed, "managed-settings.json"), map[string]any{"disableAllHooks": true})
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command("echo stop"))})
	agent, _ := h.scan()
	if r := agent.Hooks[0]; r.Enablement.State != hookUnresolved || slices.Contains(r.Enablement.Reasons, HookReasonDisableAllHooks) || !slices.Contains(r.Enablement.Reasons, HookReasonManagedTierShadowed) {
		t.Fatalf("%+v", r.Enablement)
	}
}

// A newline splits one command into two for the shell, so it is no Kontext
// call even when its words name the installed binary.
func TestKontextCallNeedsOneLiteralCommand(t *testing.T) {
	h := newHookHome(t)
	bin := h.write(filepath.Join(h.home, "bin", "kontext"), []byte("#!/bin/sh\n"))
	quoted := agenthooks.ShellQuote(bin)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": map[string]any{
		"PreToolUse": []any{map[string]any{"matcher": "*", "hooks": []any{command(quoted + "\nhook pre-tool-use")}}},
		"Stop":       []any{map[string]any{"hooks": []any{command(quoted + " hook stop")}}},
	}})
	agent, _ := h.scan(bin)
	if r := byEvent(agent, "PreToolUse")[0]; r.Origin == HookOriginKontext {
		t.Fatalf("split command verified as Kontext's: %+v", r)
	}
	if r := byEvent(agent, "Stop")[0]; r.Origin != HookOriginKontext || *r.Summary != "kontext hook stop" {
		t.Fatalf("literal call %+v", r)
	}
}

// An attached short-flag value is a value: -pSECRET never reads as a flag.
func TestHookSummaryDropsAttachedFlagValues(t *testing.T) {
	got := hookSummary("mysql", []string{"-pExamplePass123", "-u", "root", "--host=db"})
	if got != "mysql <redacted> -u <redacted> --host <redacted>" {
		t.Fatalf("summary %q", got)
	}
}

// Ownership needs the canonical path: a symlink followed by ".." can resolve
// into a folder the cleaned spelling avoids.
func TestKontextCallNeedsACanonicalPath(t *testing.T) {
	h := newHookHome(t)
	bin := filepath.Join(h.home, "bin", "kontext")
	odd := filepath.Join(h.home, "bin") + string(filepath.Separator) + "link" + string(filepath.Separator) + ".." + string(filepath.Separator) + "kontext"
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command(agenthooks.ShellQuote(odd)+" hook stop"))})
	agent, _ := h.scan(bin, odd)
	if r := agent.Hooks[0]; r.Origin == HookOriginKontext {
		t.Fatalf("non-canonical path verified: %+v", r)
	}
}

// An event key that reads as a secret is never reported.
func TestSecretEventNamesAreDropped(t *testing.T) {
	h := newHookHome(t)
	token := "ghp_" + strings.Repeat("a1", 18)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": map[string]any{
		token:  []any{map[string]any{"hooks": []any{command("notify.sh")}}},
		"Stop": []any{map[string]any{"hooks": []any{command("notify.sh")}}},
	}})
	agent, result := h.scan()
	data, _ := json.Marshal(agent)
	if strings.Contains(string(data), token) || len(agent.Hooks) != 1 || result.Status == StatusComplete {
		t.Fatalf("result %+v agent %s", result, data)
	}
}

// A plugin whose manifest says defaultEnabled false is off until a setting
// turns it on.
func TestDefaultOffPluginIsDisabled(t *testing.T) {
	h := newHookHome(t)
	h.installPlugin("formatter@acme", nil, hooksOf("Stop", "", command("format.sh")))
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	h.write(filepath.Join(dir, ".claude-plugin/plugin.json"), map[string]any{"name": "formatter", "version": "1.4.0", "defaultEnabled": false})
	agent, _ := h.scan()
	if r := agent.Hooks[0]; r.Enablement.State != "disabled" || !slices.Contains(r.Enablement.Reasons, HookReasonPluginDisabled) {
		t.Fatalf("%+v", r.Enablement)
	}
	on := true
	h.installPlugin("formatter@acme", &on, hooksOf("Stop", "", command("format.sh")))
	h.write(filepath.Join(dir, ".claude-plugin/plugin.json"), map[string]any{"name": "formatter", "version": "1.4.0", "defaultEnabled": false})
	agent, _ = h.scan()
	if r := agent.Hooks[0]; slices.Contains(r.Enablement.Reasons, HookReasonPluginDisabled) {
		t.Fatalf("turned on: %+v", r.Enablement)
	}
}

// Two spellings of one project are one scope, so the block stays valid.
func TestEquivalentProjectKeysShareAScope(t *testing.T) {
	h := newHookHome(t)
	project := filepath.Join(h.home, "src", "app")
	h.write(filepath.Join(project, ".claude", "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", command("notify.sh"))})
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{project: map[string]any{}, project + string(filepath.Separator): map[string]any{}}})
	agent, _ := h.scan()
	ids := map[string]bool{}
	for _, scope := range agent.Scopes {
		if ids[scope.ID] {
			t.Fatalf("duplicate scope %s", scope.ID)
		}
		ids[scope.ID] = true
	}
	if len(agent.Hooks) != 1 {
		t.Fatalf("hooks %+v", agent.Hooks)
	}
}

// A hooks file the manifest names but that isn't there leaves its scope
// partial: what it holds may exist.
func TestMissingDeclaredPluginFileIsPartial(t *testing.T) {
	h := newHookHome(t)
	h.installPlugin("formatter@acme", nil, hooksOf("Stop", "", command("format.sh")))
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	h.write(filepath.Join(dir, ".claude-plugin/plugin.json"), map[string]any{"name": "formatter", "version": "1.4.0", "hooks": "./extra-hooks.json"})
	agent, result := h.scan()
	scope := scopeOf(agent, agent.Hooks[0].ScopeID)
	if scope.Status == StatusComplete || result.Status == StatusComplete {
		t.Fatalf("scope %+v result %+v", scope, result)
	}
}

// A manifest naming the default file explicitly still needs it: the default
// read finding it absent doesn't make the scope complete.
func TestExplicitDefaultPluginFileMustExist(t *testing.T) {
	h := newHookHome(t)
	h.installPlugin("formatter@acme", nil, hooksOf("Stop", "", command("format.sh")))
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	if err := os.Remove(filepath.Join(dir, "hooks/hooks.json")); err != nil {
		t.Fatal(err)
	}
	h.write(filepath.Join(dir, ".claude-plugin/plugin.json"), map[string]any{"name": "formatter", "version": "1.4.0", "hooks": "./hooks/hooks.json"})
	agent, _ := h.scan()
	for _, scope := range agent.Scopes {
		if scope.Kind == HookScopePlugin && scope.Status == StatusComplete {
			t.Fatalf("plugin scope %+v", scope)
		}
	}
}

// Managed files an MDM profile replaced don't switch plugins off either.
func TestShadowedManagedPluginSwitchIsNotInForce(t *testing.T) {
	h := newHookHome(t)
	h.mdm = true
	h.installPlugin("formatter@acme", nil, hooksOf("Stop", "", command("format.sh")))
	h.write(filepath.Join(h.managed, "managed-settings.json"), map[string]any{"enabledPlugins": map[string]any{"formatter@acme": false}})
	agent, _ := h.scan()
	r := byEvent(agent, "Stop")[0]
	if r.Enablement.State != hookUnresolved || slices.Contains(r.Enablement.Reasons, HookReasonPluginDisabled) {
		t.Fatalf("%+v", r.Enablement)
	}
}

// An MDM profile with only managedSourcesBehavior supplies no policy.
func TestMDMProfileNeedsPolicyKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	xmlPlist := func(keys ...string) []byte {
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>`)
		for _, key := range keys {
			b.WriteString("<key>" + key + "</key><dict><key>nested</key><true/></dict>")
		}
		b.WriteString("</dict></plist>")
		return []byte(b.String())
	}
	for name, test := range map[string]struct {
		data []byte
		want bool
	}{
		"xml behavior only":    {xmlPlist(mdmBehaviorKey), false},
		"xml with policy":      {xmlPlist(mdmBehaviorKey, "hooks"), true},
		"binary behavior only": {binaryPlist(mdmBehaviorKey), false},
		"binary with policy":   {binaryPlist(mdmBehaviorKey, "disableAllHooks"), true},
		"unreadable":           {[]byte("bplist00garbage"), true},
		"xml merge":            {[]byte(`<?xml version="1.0"?><plist version="1.0"><dict><key>` + mdmBehaviorKey + `</key><string>merge</string><key>hooks</key><dict/></dict></plist>`), false},
		"binary merge":         {binaryPlistStrings(mdmBehaviorKey, "merge", "disableAllHooks", "x"), false},
		"binary replace":       {binaryPlistStrings(mdmBehaviorKey, "replace", "disableAllHooks", "x"), true},
		"overflowing count":    {overflowingPlist(), true},
	} {
		t.Run(name, func(t *testing.T) {
			if got := mdmPlistSuppliesPolicy(write(strings.ReplaceAll(name, " ", "-")+".plist", test.data)); got != test.want {
				t.Fatalf("policy = %v, want %v", got, test.want)
			}
		})
	}
	if mdmPlistSuppliesPolicy(filepath.Join(dir, "absent.plist")) {
		t.Fatal("an absent profile supplies policy")
	}
	// Merge keeps the files in force beside the profile.
	if mode := mdmPlistMode(write("merge.plist", binaryPlistStrings(mdmBehaviorKey, "merge", "hooks", "x"))); mode != mdmMerge {
		t.Fatalf("merge mode = %v", mode)
	}
}

// binaryPlistStrings encodes a dictionary of key, value string pairs.
func binaryPlistStrings(pairs ...string) []byte {
	var body bytes.Buffer
	body.WriteString("bplist00")
	offsets := []int{}
	object := func(b []byte) { offsets = append(offsets, body.Len()); body.Write(b) }
	n := len(pairs) / 2
	dict := []byte{0xD0 | byte(n)}
	for i := range n {
		dict = append(dict, byte(1+2*i))
	}
	for i := range n {
		dict = append(dict, byte(2+2*i))
	}
	object(dict)
	for _, str := range pairs {
		marker := []byte{0x50 | byte(len(str))}
		if len(str) >= 15 {
			marker = []byte{0x5F, 0x10, byte(len(str))}
		}
		object(append(marker, str...))
	}
	table := body.Len()
	for _, at := range offsets {
		body.WriteByte(byte(at))
	}
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 1, 1
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(offsets)))
	binary.BigEndian.PutUint64(trailer[24:], uint64(table))
	body.Write(trailer)
	return body.Bytes()
}

// overflowingPlist's top dictionary claims 2^64-1 entries.
func overflowingPlist() []byte {
	var body bytes.Buffer
	body.WriteString("bplist00")
	body.Write([]byte{0xDF, 0x13, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	table := body.Len()
	body.WriteByte(8)
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 1, 1
	binary.BigEndian.PutUint64(trailer[8:], 1)
	binary.BigEndian.PutUint64(trailer[24:], uint64(table))
	body.Write(trailer)
	return body.Bytes()
}

// binaryPlist encodes a dictionary of the keys, each mapped to true, as
// bplist00 with one-byte offsets and references.
func binaryPlist(keys ...string) []byte {
	var body bytes.Buffer
	body.WriteString("bplist00")
	offsets := []int{}
	object := func(b []byte) { offsets = append(offsets, body.Len()); body.Write(b) }
	n := len(keys)
	dict := []byte{0xD0 | byte(n)}
	for i := range keys {
		dict = append(dict, byte(1+i))
	}
	for range keys {
		dict = append(dict, byte(1+n))
	}
	object(dict)
	for _, key := range keys {
		marker := []byte{0x50 | byte(len(key))}
		if len(key) >= 15 {
			marker = []byte{0x5F, 0x10, byte(len(key))}
		}
		object(append(marker, key...))
	}
	object([]byte{0x09})
	table := body.Len()
	for _, at := range offsets {
		body.WriteByte(byte(at))
	}
	trailer := make([]byte, 32)
	trailer[6], trailer[7] = 1, 1
	binary.BigEndian.PutUint64(trailer[8:], uint64(len(offsets)))
	binary.BigEndian.PutUint64(trailer[24:], uint64(table))
	body.Write(trailer)
	return body.Bytes()
}

// A token a generated manifest put in a plugin's version never leaves.
func TestPluginMetadataHidesTokens(t *testing.T) {
	h := newHookHome(t)
	on := true
	h.installPlugin("formatter@acme", &on, hooksOf("Stop", "", command("echo stop")))
	token := "npm_" + strings.Repeat("a1B2", 9)
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	h.write(filepath.Join(dir, ".claude-plugin/plugin.json"), map[string]any{"name": "formatter", "version": token})
	agent, _ := h.scan()
	if len(agent.Hooks) != 1 || agent.Hooks[0].Plugin == nil || *agent.Hooks[0].Plugin.Version != redacted {
		t.Fatalf("%+v", agent.Hooks)
	}
}
