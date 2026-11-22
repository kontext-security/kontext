package agentauthority

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// claudeCodeChecked is the Claude Code release whose documented behaviour
// the enablement rules follow (settings reference and hooks reference,
// "Hook locations" and "Disable or remove hooks"). When a later release
// changes a rule, change the rule, its row below and this version together.
const claudeCodeChecked = "2.1.329"

// enablementRule is one row of the enablement matrix: the settings that
// trigger a rule and the state and reasons the hook it targets ends with.
type enablementRule struct {
	name string
	// claudeCode is the release the row's behaviour was checked against.
	claudeCode string
	// follows names the documented behaviour.
	follows string
	setup   func(h *hookHome) (event string)
	state   string
	reasons []string
}

// skillFile is a SKILL.md, or a subagent file, whose frontmatter declares
// one command hook.
func skillFile(event, line string) []byte {
	return []byte("---\nname: deploy\ndescription: Deploy things\nhooks:\n  " + event + ":\n    - matcher: \"Bash\"\n      hooks:\n        - type: command\n          command: \"" + line + "\"\n---\n\nBody text.\n")
}

func enablementMatrix() []enablementRule {
	userHook := func(h *hookHome, event string, handler map[string]any, extra map[string]any) {
		settings := map[string]any{"hooks": hooksOf(event, "", handler)}
		for k, v := range extra {
			settings[k] = v
		}
		h.write(filepath.Join(h.base, "settings.json"), settings)
	}
	managed := func(h *hookHome, settings map[string]any) {
		h.write(filepath.Join(h.managed, "managed-settings.json"), settings)
	}
	http := func(url string) map[string]any { return map[string]any{"type": "http", "url": url} }
	project := func(h *hookHome, trusted bool, settings map[string]any) string {
		dir := filepath.Join(h.home, "src", "app")
		h.write(filepath.Join(dir, ".claude", "settings.json"), settings)
		h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{dir: map[string]any{"hasTrustDialogAccepted": trusted}}})
		return dir
	}
	return []enablementRule{
		{
			name: "a user hook runs", follows: "hooks merge across settings levels",
			setup: func(h *hookHome) string { userHook(h, "Stop", command("echo stop"), nil); return "Stop" },
			state: hookEnabled, reasons: []string{},
		},
		{
			name: "user disableAllHooks turns off a user hook", follows: "disableAllHooks in any settings file",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", command("echo stop"), map[string]any{"disableAllHooks": true})
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonDisableAllHooks},
		},
		{
			name: "user disableAllHooks leaves a managed hook on", follows: "only disableAllHooks at the managed level disables managed hooks",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"hooks": hooksOf("Stop", "", command("echo stop"))})
				h.write(filepath.Join(h.base, "settings.json"), map[string]any{"disableAllHooks": true})
				return "Stop"
			},
			state: hookEnabled, reasons: []string{},
		},
		{
			name: "managed disableAllHooks turns off a managed hook", follows: "disableAllHooks respects the managed settings hierarchy",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"disableAllHooks": true, "hooks": hooksOf("Stop", "", command("echo stop"))})
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonDisableAllHooks},
		},
		{
			name: "project disableAllHooks false lifts a user true", follows: "Claude reads the value left after settings precedence",
			setup: func(h *hookHome) string {
				h.write(filepath.Join(h.base, "settings.json"), map[string]any{"disableAllHooks": true})
				project(h, true, map[string]any{"disableAllHooks": false, "hooks": hooksOf("Stop", "", command("echo stop"))})
				return "Stop"
			},
			state: hookEnabled, reasons: []string{},
		},
		{
			name: "allowManagedHooksOnly blocks a user hook", follows: "allowManagedHooksOnly blocks user, project and local hooks",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"allowManagedHooksOnly": true})
				userHook(h, "Stop", command("echo stop"), nil)
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonManagedOnly},
		},
		{
			name: "allowManagedHooksOnly keeps a managed hook", follows: "allowManagedHooksOnly keeps the organization's hooks",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"allowManagedHooksOnly": true, "hooks": hooksOf("Stop", "", command("echo stop"))})
				return "Stop"
			},
			state: hookEnabled, reasons: []string{},
		},
		{
			name: "allowManagedHooksOnly blocks a plugin hook", follows: "allowManagedHooksOnly blocks plugin hooks (v2.1.229 and later)",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"allowManagedHooksOnly": true})
				h.installPlugin("formatter@acme", nil, hooksOf("Stop", "", command("echo stop")))
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonManagedOnly},
		},
		{
			name: "allowManagedHooksOnly keeps a plugin managed settings force-enable", follows: "hooks of plugins force-enabled in managed enabledPlugins are exempt",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"allowManagedHooksOnly": true, "enabledPlugins": map[string]any{"formatter@acme": true}})
				h.installPlugin("formatter@acme", nil, hooksOf("Stop", "", command("echo stop")))
				return "Stop"
			},
			state: hookEnabled, reasons: []string{},
		},
		{
			name: "strictPluginOnlyCustomization blocks a user hook", follows: "strictPluginOnlyCustomization locks hooks to plugin and managed sources",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"strictPluginOnlyCustomization": []string{"hooks"}})
				userHook(h, "Stop", command("echo stop"), nil)
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonPluginOnly},
		},
		{
			name: "strictPluginOnlyCustomization keeps a plugin hook", follows: "strictPluginOnlyCustomization locks hooks to plugin and managed sources",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"strictPluginOnlyCustomization": true})
				h.installPlugin("formatter@acme", nil, hooksOf("Stop", "", command("echo stop")))
				return "Stop"
			},
			state: hookEnabled, reasons: []string{},
		},
		{
			name: "a disabled plugin's hook doesn't run", follows: "enabledPlugins",
			setup: func(h *hookHome) string {
				off := false
				h.installPlugin("formatter@acme", &off, hooksOf("Stop", "", command("echo stop")))
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonPluginDisabled},
		},
		{
			name: "a managed allowlist blocks another URL", follows: "allowedHttpHookUrls, the merged allowlist",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"allowedHttpHookUrls": []string{"https://hooks.example.com/*"}})
				userHook(h, "Stop", http("https://other.example.com/x"), nil)
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonHTTPURLNotAllowed},
		},
		{
			name: "a user allowlist blocks another URL", follows: "allowedHttpHookUrls when defined at any settings level",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", http("https://other.example.com/x"), map[string]any{"allowedHttpHookUrls": []string{"https://hooks.example.com/*"}})
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonHTTPURLNotAllowed},
		},
		{
			name: "a user allowlist alone leaves a managed hook unsettled", follows: "the HTTP hook allowlists apply to hooks from every source",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"hooks": hooksOf("Stop", "", http("https://other.example.com/x"))})
				h.write(filepath.Join(h.base, "settings.json"), map[string]any{"allowedHttpHookUrls": []string{"https://hooks.example.com/*"}})
				return "Stop"
			},
			// Only a user file defines the list: whether it applies to a
			// managed hook isn't settled.
			state: hookUnresolved, reasons: []string{HookReasonHTTPURLNotAllowed},
		},
		{
			name: "the host matches in any case and without a trailing dot", follows: "allowedHttpHookUrls matches the URL's normalized host",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", http("https://Hooks.Example.COM./Path"), map[string]any{"allowedHttpHookUrls": []string{"https://HOOKS.example.com/Path"}})
				return "Stop"
			},
			state: hookEnabled, reasons: []string{},
		},
		{
			name: "the path keeps its case", follows: "allowedHttpHookUrls matches the URL's normalized host",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", http("https://hooks.example.com/path"), map[string]any{"allowedHttpHookUrls": []string{"https://hooks.example.com/Path"}})
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonHTTPURLNotAllowed},
		},
		{
			name: "a user hook a project's list allows runs in that project", follows: "a user hook runs in every project, under that project's merged allowlist",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", http("https://other.example.com/x"), map[string]any{"allowedHttpHookUrls": []string{"https://hooks.example.com/*"}})
				project(h, true, map[string]any{"allowedHttpHookUrls": []string{"https://other.example.com/*"}})
				return "Stop"
			},
			state: hookConditional, reasons: []string{HookReasonHTTPURLNotAllowed},
		},
		{
			name: "a project allowlist adds to the managed one", follows: "the merged allowlist",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"allowedHttpHookUrls": []string{"https://hooks.example.com/*"}})
				project(h, true, map[string]any{"allowedHttpHookUrls": []string{"https://other.example.com/*"}, "hooks": hooksOf("Stop", "", http("https://other.example.com/x"))})
				return "Stop"
			},
			state: hookEnabled, reasons: []string{},
		},
		{
			name: "a managed entry still allows a project hook beside the project's own", follows: "the merged allowlist adds, never replaces",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"allowedHttpHookUrls": []string{"https://hooks.example.com/*"}})
				project(h, true, map[string]any{"allowedHttpHookUrls": []string{"https://other.example.com/*"}, "hooks": hooksOf("Stop", "", http("https://hooks.example.com/x"))})
				return "Stop"
			},
			state: hookEnabled, reasons: []string{},
		},
		{
			name: "a project's own empty allowlist blocks a user hook there", follows: "a user hook runs in every project, under that project's merged allowlist",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", http("https://hooks.example.com/x"), nil)
				project(h, true, map[string]any{"allowedHttpHookUrls": []string{}})
				return "Stop"
			},
			state: hookConditional, reasons: []string{HookReasonHTTPURLNotAllowed},
		},
		{
			name: "a project that allows the URL but turns hooks off runs nothing", follows: "disableAllHooks in any settings file",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", http("https://other.example.com/x"), map[string]any{"allowedHttpHookUrls": []string{"https://hooks.example.com/*"}})
				project(h, true, map[string]any{"allowedHttpHookUrls": []string{"https://other.example.com/*"}, "disableAllHooks": true})
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonHTTPURLNotAllowed},
		},
		{
			name: "an unread project file leaves a blocked user hook unsettled", follows: "any settings file may add the URL",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", http("https://other.example.com/x"), map[string]any{"allowedHttpHookUrls": []string{}})
				dir := project(h, true, map[string]any{})
				h.write(filepath.Join(dir, ".claude", "settings.local.json"), []byte(`{"allowedHttpHookUrls": [`))
				return "Stop"
			},
			state: hookUnresolved, reasons: []string{HookReasonHTTPURLNotAllowed},
		},
		{
			name: "user information keeps its case", follows: "allowedHttpHookUrls matches the URL's normalized host",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", http("https://bot:abc@hooks.example.com/x"), map[string]any{"allowedHttpHookUrls": []string{"https://bot:ABC@hooks.example.com/x"}})
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonHTTPURLNotAllowed},
		},
		{
			name: "an unreadable managed enabledPlugins leaves a plugin hook unsettled", follows: "hooks of plugins force-enabled in managed enabledPlugins are exempt",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"allowManagedHooksOnly": true, "enabledPlugins": map[string]any{"formatter@acme": true, "other@acme": "yes"}})
				h.installPlugin("formatter@acme", nil, hooksOf("Stop", "", command("echo stop")))
				return "Stop"
			},
			state: hookUnresolved, reasons: []string{HookReasonManagedOnly, HookReasonUnresolved},
		},
		{
			name: "an empty allowlist blocks every URL", follows: "allowedHttpHookUrls when defined",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", http("https://hooks.example.com/x"), map[string]any{"allowedHttpHookUrls": []string{}})
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonHTTPURLNotAllowed},
		},
		{
			name: "an untrusted project's hook waits for trust", follows: "project settings apply once the folder is trusted",
			setup: func(h *hookHome) string {
				project(h, false, map[string]any{"hooks": hooksOf("Stop", "", command("echo stop"))})
				return "Stop"
			},
			state: hookConditional, reasons: []string{HookReasonAwaitingTrust},
		},
		{
			name: "a missing program can't run", follows: "a command hook runs its program",
			setup: func(h *hookHome) string {
				// Exec form: the path is the program as written on every
				// platform, with no shell escapes.
				userHook(h, "Stop", map[string]any{"type": "command", "command": filepath.Join(h.home, "bin", "gone"), "args": []string{}}, nil)
				return "Stop"
			},
			state: hookDisabled, reasons: []string{HookReasonBinaryMissing},
		},
		{
			name: "an MDM profile shadows the managed files", follows: "Claude Code uses one managed source",
			setup: func(h *hookHome) string {
				h.mdm = true
				managed(h, map[string]any{"hooks": hooksOf("Stop", "", command("echo stop"))})
				return "Stop"
			},
			state: hookUnresolved, reasons: []string{HookReasonManagedTierShadowed},
		},
		{
			name: "unlistable drop-ins leave every hook unresolved", follows: "managed-settings.d merges by file name",
			setup: func(h *hookHome) string {
				h.write(filepath.Join(h.managed, "managed-settings.d"), []byte("not a folder"))
				userHook(h, "Stop", command("echo stop"), nil)
				return "Stop"
			},
			state: hookUnresolved, reasons: []string{HookReasonDropInUnlistable},
		},
		{
			name: "a skill's hooks run while it is active", follows: "skill frontmatter hooks apply once the skill is invoked",
			setup: func(h *hookHome) string {
				h.write(filepath.Join(h.base, "skills", "deploy", "SKILL.md"), skillFile("PreToolUse", "echo check"))
				return "PreToolUse"
			},
			state: hookConditional, reasons: []string{HookReasonWhileActive},
		},
		{
			name: "an untrusted project's skill waits for trust too", follows: "project skill hooks follow the workspace trust rule",
			setup: func(h *hookHome) string {
				dir := project(h, false, map[string]any{})
				h.write(filepath.Join(dir, ".claude", "skills", "deploy", "SKILL.md"), skillFile("PreToolUse", "echo check"))
				return "PreToolUse"
			},
			state: hookConditional, reasons: []string{HookReasonAwaitingTrust, HookReasonWhileActive},
		},
		{
			name: "strictPluginOnlyCustomization drops a personal skill's hooks", follows: "a skill keeps frontmatter hooks under the lock only from a plugin or managed settings",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"strictPluginOnlyCustomization": true})
				h.write(filepath.Join(h.base, "skills", "deploy", "SKILL.md"), skillFile("PreToolUse", "echo check"))
				return "PreToolUse"
			},
			state: hookDisabled, reasons: []string{HookReasonPluginOnly, HookReasonWhileActive},
		},
		{
			name: "strictPluginOnlyCustomization keeps a managed skill's hooks", follows: "a skill keeps frontmatter hooks under the lock only from a plugin or managed settings",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"strictPluginOnlyCustomization": true})
				h.write(filepath.Join(h.managed, ".claude", "skills", "deploy", "SKILL.md"), skillFile("PreToolUse", "echo check"))
				return "PreToolUse"
			},
			state: hookConditional, reasons: []string{HookReasonWhileActive},
		},
		{
			name: "a skills lock drops a personal skill's hooks", follows: "strictPluginOnlyCustomization skills keeps skills to plugin and managed sources",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"strictPluginOnlyCustomization": []string{"skills"}})
				h.write(filepath.Join(h.base, "skills", "deploy", "SKILL.md"), skillFile("PreToolUse", "echo check"))
				return "PreToolUse"
			},
			state: hookDisabled, reasons: []string{HookReasonPluginOnly, HookReasonWhileActive},
		},
		{
			name: "an agents lock drops a personal subagent's hooks", follows: "strictPluginOnlyCustomization agents keeps subagents to plugin and managed sources",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"strictPluginOnlyCustomization": []string{"agents"}})
				h.write(filepath.Join(h.base, "agents", "reviewer.md"), skillFile("PreToolUse", "echo check"))
				return "PreToolUse"
			},
			state: hookDisabled, reasons: []string{HookReasonPluginOnly, HookReasonWhileActive},
		},
		{
			name: "a skills lock leaves a subagent's hooks alone", follows: "strictPluginOnlyCustomization locks only the surfaces it names",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"strictPluginOnlyCustomization": []string{"skills"}})
				h.write(filepath.Join(h.base, "agents", "reviewer.md"), skillFile("PreToolUse", "echo check"))
				return "PreToolUse"
			},
			state: hookConditional, reasons: []string{HookReasonWhileActive},
		},
		{
			name: "a skills lock leaves a settings hook alone", follows: "strictPluginOnlyCustomization locks only the surfaces it names",
			setup: func(h *hookHome) string {
				managed(h, map[string]any{"strictPluginOnlyCustomization": []string{"skills", "agents"}})
				userHook(h, "Stop", command("echo stop"), nil)
				return "Stop"
			},
			state: hookEnabled, reasons: []string{},
		},
		{
			name: "a claude.ai sign-in is named without changing the state", follows: "server-managed settings apply to signed-in organizations",
			setup: func(h *hookHome) string {
				userHook(h, "Stop", command("echo stop"), nil)
				h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"oauthAccount": map[string]any{"organizationUuid": "org-1"}})
				return "Stop"
			},
			state: hookEnabled, reasons: []string{HookReasonRemoteManagedUnverified},
		},
	}
}

func TestEnablementMatrix(t *testing.T) {
	for _, rule := range enablementMatrix() {
		t.Run(rule.name, func(t *testing.T) {
			if rule.claudeCode == "" {
				rule.claudeCode = claudeCodeChecked
			}
			if rule.claudeCode != claudeCodeChecked {
				t.Fatalf("row checked against Claude Code %s, rules follow %s", rule.claudeCode, claudeCodeChecked)
			}
			h := newHookHome(t)
			event := rule.setup(h)
			agent, _ := h.scan()
			if agent.AgentVersion == nil || *agent.AgentVersion != claudeCodeChecked {
				t.Fatalf("agent_version %v", agent.AgentVersion)
			}
			records := byEvent(agent, event)
			if len(records) != 1 {
				t.Fatalf("records %+v", agent.Hooks)
			}
			got := records[0].Enablement
			if got.State != rule.state || !slices.Equal(got.Reasons, rule.reasons) {
				t.Fatalf("follows %q: got %s %v, want %s %v", rule.follows, got.State, got.Reasons, rule.state, rule.reasons)
			}
		})
	}
}

// Every reason code the scanner can set (HookEnablementReasons, the list the
// cloud contract mirrors) has a row in the matrix, except unresolved, which
// the scanner sets for cases no setting decides.
func TestEnablementMatrixCoversEveryReason(t *testing.T) {
	covered := map[string]bool{HookReasonUnresolved: true}
	for _, rule := range enablementMatrix() {
		for _, reason := range rule.reasons {
			covered[reason] = true
		}
	}
	for _, reason := range HookEnablementReasons {
		if !covered[reason] {
			t.Errorf("no matrix row for %s", reason)
		}
	}
}

// An unread settings file may add a URL to the allowlist, so a blocked URL
// is not settled while one went unread.
func TestUnreadFileLeavesABlockedURLUnresolved(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.managed, "managed-settings.json"), map[string]any{"allowedHttpHookUrls": []string{"https://hooks.example.com/*"}})
	dir := filepath.Join(h.home, "src", "app")
	h.write(filepath.Join(dir, ".claude", "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", map[string]any{"type": "http", "url": "https://other.example.com/x"})})
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{dir: map[string]any{"hasTrustDialogAccepted": true}}})
	if err := os.WriteFile(filepath.Join(dir, ".claude", "settings.local.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	agent, _ := h.scan()
	records := byEvent(agent, "Stop")
	if len(records) != 1 || records[0].Enablement.State != hookUnresolved || !slices.Contains(records[0].Enablement.Reasons, HookReasonHTTPURLNotAllowed) {
		t.Fatalf("%+v", records)
	}
}

// A list past the scan's pattern budget can't settle a block.
func TestAllowlistPastTheBudgetIsUnsettled(t *testing.T) {
	h := newHookHome(t)
	patterns := make([]string, maxURLPatterns+1)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("https://h%d.example.com/*", i)
	}
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"allowedHttpHookUrls": patterns, "hooks": hooksOf("Stop", "", map[string]any{"type": "http", "url": "https://other.example.com/x"})})
	agent, _ := h.scan()
	if r := byEvent(agent, "Stop"); len(r) != 1 || r[0].Enablement.State != hookUnresolved {
		t.Fatalf("%+v", r)
	}
}

// The force-enabled plugin exemption from allowManagedHooksOnly came with
// Claude Code 2.1.229.
func TestManagedOnlyExemptionFollowsTheVersion(t *testing.T) {
	for version, want := range map[string]int{
		"2.1.229": versionAtOrAfter, "2.1.329 (Claude Code)": versionAtOrAfter, "2.2.0": versionAtOrAfter, "3.0.0-beta": versionAtOrAfter,
		"2.1.228": versionBefore, "1.9.999": versionBefore,
		"": versionUnknown, "dev": versionUnknown, "2.1": versionUnknown,
	} {
		if got := managedOnlyExempt(version); got != want {
			t.Errorf("%q: %d, want %d", version, got, want)
		}
	}
}

// A pattern repeated in the list is tried once, and the scan's matches are
// bounded: many HTTP hooks under a long list end unsettled, not slow.
func TestAllowlistMatchesAreBounded(t *testing.T) {
	h := newHookHome(t)
	repeated := make([]string, 10000)
	for i := range repeated {
		repeated[i] = "https://hooks.example.com/*"
	}
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"allowedHttpHookUrls": repeated, "hooks": hooksOf("Stop", "", map[string]any{"type": "http", "url": "https://other.example.com/x"})})
	agent, _ := h.scan()
	if r := byEvent(agent, "Stop"); len(r) != 1 || r[0].Enablement.State != hookDisabled {
		t.Fatalf("%+v", r)
	}

	s := &hookScan{g: &guard{ctx: context.Background()}}
	patterns := make([]string, maxURLPatterns)
	for i := range patterns {
		patterns[i] = fmt.Sprintf("https://h%d.example.com/*", i)
	}
	for range maxURLMatches/maxURLPatterns + 1 {
		s.urlAllowed("https://other.example.com/x", patterns, nil)
	}
	if _, known := s.urlAllowed("https://other.example.com/x", patterns, nil); known {
		t.Fatal("matching past the budget settled the URL")
	}
}
