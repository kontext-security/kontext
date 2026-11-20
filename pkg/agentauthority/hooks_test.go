package agentauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	t.Run("managed file shadowed by MDM", func(t *testing.T) {
		h, bin, call := setup(t)
		h.mdm = true
		h.write(filepath.Join(h.managed, "managed-settings.d", "20-kontext.json"), map[string]any{"hooks": all(call, "", nil)})
		agent, _ := h.scan(bin)
		if agent.KontextHooks.State != "missing" {
			t.Fatalf("%+v", agent.KontextHooks)
		}
		if r := agent.Hooks[0]; r.Enablement.State != hookUnresolved || !slices.Contains(r.Enablement.Reasons, HookReasonManagedTierShadowed) {
			t.Fatalf("%+v", r.Enablement)
		}
	})
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

// A positional word can be a password, so only script names stay readable.
func TestHookSummaryDropsPositionalWords(t *testing.T) {
	for args, want := range map[string]string{
		"AUTH hunter2":              "redis-cli <redacted>",
		"check-secrets.sh --strict": "redis-cli check-secrets.sh --strict",
		"--verbose":                 "redis-cli --verbose",
	} {
		if got := hookSummary("/usr/bin/redis-cli", strings.Fields(args)); got != want {
			t.Errorf("hookSummary(%q) = %q, want %q", args, got, want)
		}
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
