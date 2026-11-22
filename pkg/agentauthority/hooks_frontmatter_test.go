package agentauthority

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/pkg/agentauthority/readers"
)

// Skills and subagents are scopes of their own. Those without hooks are still
// listed, so a hook removed from one is withdrawn rather than kept.
func TestFrontmatterHooksAreScopes(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "skills", "deploy", "SKILL.md"), skillFile("PreToolUse", "echo check"))
	h.write(filepath.Join(h.base, "skills", "notes", "SKILL.md"), []byte("---\nname: notes\ndescription: Take notes\n---\nBody\n"))
	h.write(filepath.Join(h.base, "skills", "empty", "README.md"), []byte("not a skill"))
	h.write(filepath.Join(h.base, "agents", "team", "reviewer.md"), skillFile("Stop", "echo done"))
	h.write(filepath.Join(h.base, "agents", "plain.md"), []byte("no frontmatter"))
	agent, result := h.scan()
	if result.Status != StatusComplete {
		t.Fatalf("result %+v", result)
	}
	withHooks := map[string]int{}
	listed := map[string]int{}
	for _, scope := range agent.Scopes {
		listed[scope.Kind]++
		for _, hook := range agent.Hooks {
			if hook.ScopeID == scope.ID {
				withHooks[scope.Kind]++
				break
			}
		}
	}
	// deploy and notes are skills, the README folder isn't; reviewer and
	// plain are subagents.
	if withHooks[HookScopeSkill] != 1 || withHooks[HookScopeSubagent] != 1 || listed[HookScopeSkill] != 2 || listed[HookScopeSubagent] != 2 {
		t.Fatalf("scopes %+v", agent.Scopes)
	}
	pre := byEvent(agent, "PreToolUse")
	if len(pre) != 1 || pre[0].Matcher == nil || *pre[0].Matcher != "Bash" || scopeOf(agent, pre[0].ScopeID).Kind != HookScopeSkill {
		t.Fatalf("skill hook %+v", pre)
	}
	// A subagent's Stop runs as SubagentStop.
	if stop := byEvent(agent, "SubagentStop"); len(stop) != 1 || len(byEvent(agent, "Stop")) != 0 {
		t.Fatalf("subagent hooks %+v", agent.Hooks)
	}
}

// A plugin's skills follow the plugin's switches; its subagents can't declare
// hooks.
func TestPluginSkillHooks(t *testing.T) {
	h := newHookHome(t)
	off := false
	h.installPlugin("formatter@acme", &off, map[string]any{})
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	h.write(filepath.Join(dir, "skills", "fmt", "SKILL.md"), skillFile("PostToolUse", "echo fmt"))
	h.write(filepath.Join(dir, "agents", "helper.md"), skillFile("PreToolUse", "echo nope"))
	agent, _ := h.scan()
	post := byEvent(agent, "PostToolUse")
	if len(post) != 1 || post[0].Plugin == nil || post[0].Origin != HookOriginPlugin {
		t.Fatalf("plugin skill %+v", agent.Hooks)
	}
	if e := post[0].Enablement; e.State != hookDisabled || !slices.Contains(e.Reasons, HookReasonPluginDisabled) {
		t.Fatalf("%+v", e)
	}
	if len(byEvent(agent, "PreToolUse")) != 0 {
		t.Fatal("a plugin subagent's hooks were read")
	}
}

// Unparsed frontmatter fails its scope, and the folders are read within
// bounds.
func TestFrontmatterHealthAndBounds(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "skills", "broken", "SKILL.md"), []byte("---\nhooks: [unclosed\n---\n"))
	agent, result := h.scan()
	if result.Status != StatusPartial || len(agent.Scopes) == 0 {
		t.Fatalf("result %+v scopes %+v", result, agent.Scopes)
	}
	var broken *HookScope
	for i := range agent.Scopes {
		if agent.Scopes[i].Kind == HookScopeSkill {
			broken = &agent.Scopes[i]
		}
	}
	if broken == nil || broken.Status != StatusFailed || !slices.Equal(broken.Reasons, []string{ReasonMalformed}) {
		t.Fatalf("broken skill scope %+v", broken)
	}

	h = newHookHome(t)
	for i := range maxFrontmatterFiles + 1 {
		h.write(filepath.Join(h.base, "skills", fmt.Sprintf("s%03d", i), "SKILL.md"), skillFile("Stop", "echo stop"))
	}
	h.write(filepath.Join(h.base, "agents", "a", "b", "c", "deep.md"), skillFile("Stop", "echo deep"))
	agent, result = h.scan()
	if !agent.Truncated || result.Status != StatusPartial || !slices.Contains(result.Reasons, ReasonWalkLimit) {
		t.Fatalf("truncated %v result %+v", agent.Truncated, result)
	}
	if got := len(byEvent(agent, "Stop")); got != maxFrontmatterFiles {
		t.Fatalf("%d skill hooks", got)
	}
	if len(byEvent(agent, "SubagentStop")) != 0 {
		t.Fatal("a subagent past the depth bound was read")
	}
}

// A secret in a frontmatter hook's command never reaches the summary.
func TestFrontmatterHooksAreRedacted(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "skills", "db", "SKILL.md"), skillFile("PreToolUse", "mysql -pFAKEhunter2 appdb"))
	agent, _ := h.scan()
	if len(byEvent(agent, "PreToolUse")) != 1 {
		t.Fatalf("no record to check: %+v", agent.Hooks)
	}
	data, err := json.Marshal(agent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "FAKEhunter2") {
		t.Fatalf("agent %s", data)
	}
}

// An MCP server or tool written as a path shows redacted.
func TestMCPToolNamesAreRedacted(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf("Stop", "", map[string]any{"type": "mcp_tool", "server": "/Users/someone/FAKEhunter2", "tool": "notify"})})
	agent, _ := h.scan()
	stop := byEvent(agent, "Stop")
	if len(stop) != 1 || stop[0].Summary == nil || *stop[0].Summary != redacted+"/notify" {
		t.Fatalf("mcp hooks %+v", stop)
	}
}

// What the scan doesn't follow leaves it partial: a symlinked skill or
// subagent, and skill folders a plugin's manifest names.
func TestUnreadSkillsLeaveTheScanPartial(t *testing.T) {
	h := newHookHome(t)
	target := filepath.Join(h.home, "elsewhere")
	h.write(filepath.Join(target, "SKILL.md"), skillFile("Stop", "echo stop"))
	if err := os.MkdirAll(filepath.Join(h.base, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(h.base, "skills", "linked")); err != nil {
		t.Fatal(err)
	}
	if _, result := h.scan(); result.Status != StatusPartial || !slices.Contains(result.Reasons, ReasonUnsupportedFormat) {
		t.Fatalf("symlinked skill %+v", result)
	}

	h = newHookHome(t)
	h.write(filepath.Join(h.home, "elsewhere.md"), skillFile("Stop", "echo stop"))
	if err := os.MkdirAll(filepath.Join(h.base, "agents"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(h.home, "elsewhere.md"), filepath.Join(h.base, "agents", "linked.md")); err != nil {
		t.Fatal(err)
	}
	if _, result := h.scan(); result.Status != StatusPartial || !slices.Contains(result.Reasons, ReasonUnsupportedFormat) {
		t.Fatalf("symlinked subagent %+v", result)
	}

	h = newHookHome(t)
	h.installPlugin("formatter@acme", nil, map[string]any{})
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	h.write(filepath.Join(dir, ".claude-plugin/plugin.json"), map[string]any{"name": "formatter", "version": "1.4.0", "skills": "./extra"})
	if _, result := h.scan(); result.Status != StatusPartial || !slices.Contains(result.Reasons, ReasonUnsupportedFormat) {
		t.Fatalf("manifest skills %+v", result)
	}
}

// A wide subagents folder is listed within a budget, and the cut truncates
// the scan.
func TestSubagentListingsAreBounded(t *testing.T) {
	h := newHookHome(t)
	for i := range maxAgentListings + 1 {
		h.write(filepath.Join(h.base, "agents", fmt.Sprintf("team%02d", i), "a.md"), []byte("no frontmatter"))
	}
	agent, result := h.scan()
	if !agent.Truncated || result.Status != StatusPartial || !slices.Contains(result.Reasons, ReasonWalkLimit) {
		t.Fatalf("truncated %v result %+v", agent.Truncated, result)
	}
}

func TestFrontmatterReader(t *testing.T) {
	for _, tc := range []struct {
		in     string
		events []string
		err    bool
	}{
		{"---\nhooks:\n  Stop:\n    - hooks:\n        - type: command\n          command: x\n---\n", []string{"Stop"}, false},
		{"\xef\xbb\xbf---\r\nhooks:\r\n  Stop:\r\n    - hooks:\r\n        - type: command\r\n          command: x\r\n---\r\n", []string{"Stop"}, false},
		{"no frontmatter\nhooks: {}\n", nil, false},
		{"---\nname: x\n", nil, false},
		{"---\n---\n", nil, false},
		{"---\nhooks: [1, 2]\n---\n", nil, true},
		{"---\nhooks:\n  1: x\n---\n", nil, true},
		{"---\n" + wideMapping(maxPairsForTest+1) + "hooks: {}\n---\n", nil, true},
		{"---\nshared: &h\n  Stop: []\nhooks: *h\n---\n", nil, true},
		{"---\nhooks:\n  Stop: " + strings.Repeat("[", 40) + strings.Repeat("]", 40) + "\n---\n", nil, true},
	} {
		got, err := readers.FrontmatterHooks([]byte(tc.in))
		if (err != nil) != tc.err {
			t.Fatalf("%q: err %v", tc.in, err)
		}
		if events := keys(got.Hooks); !slices.Equal(events, tc.events) && !(len(events) == 0 && len(tc.events) == 0) {
			t.Fatalf("%q: events %v", tc.in, events)
		}
	}
}

// One cached plugin installed for the user and for a project has two scopes
// for each skill, keyed under the install, since each follows its own
// project's settings.
func TestPluginSkillScopesFollowTheInstall(t *testing.T) {
	h := newHookHome(t)
	h.installPlugin("formatter@acme", nil, map[string]any{})
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	project := filepath.Join(h.home, "work", "app")
	h.write(filepath.Join(h.base, "plugins/installed_plugins.json"), map[string]any{"plugins": map[string]any{"formatter@acme": []any{
		map[string]any{"installPath": dir},
		map[string]any{"installPath": dir, "projectPath": project, "scope": "project"},
	}}})
	h.write(filepath.Join(dir, "skills", "fmt", "SKILL.md"), skillFile("PostToolUse", "echo fmt"))
	agent, _ := h.scan()
	post := byEvent(agent, "PostToolUse")
	if len(post) != 2 || post[0].ScopeID == post[1].ScopeID {
		t.Fatalf("plugin skill hooks %+v", post)
	}
	ids := map[string]bool{}
	for _, scope := range agent.Scopes {
		if ids[scope.ID] {
			t.Fatalf("duplicate scope %s", scope.ID)
		}
		ids[scope.ID] = true
	}
}

// A subagent folder cut at the depth bound truncates the scan, as a file
// bound does.
func TestSubagentDepthTruncates(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "agents", "a", "b", "c", "deep.md"), skillFile("Stop", "echo deep"))
	agent, result := h.scan()
	if !agent.Truncated || result.Status != StatusPartial || !slices.Contains(result.Reasons, ReasonWalkLimit) {
		t.Fatalf("truncated %v result %+v", agent.Truncated, result)
	}
}

// Settings files are read before skills and subagents take any of the scope
// cap, so many skills never crowd out a project's settings.
func TestFrontmatterComesAfterSettings(t *testing.T) {
	h := newHookHome(t)
	for _, dir := range []string{filepath.Join(h.managed, ".claude"), h.base} {
		for i := range maxFrontmatterFiles {
			h.write(filepath.Join(dir, "skills", fmt.Sprintf("s%03d", i), "SKILL.md"), skillFile("Stop", "echo stop"))
		}
	}
	for i := range maxFrontmatterFiles {
		h.write(filepath.Join(h.base, "agents", fmt.Sprintf("a%03d.md", i)), skillFile("Stop", "echo stop"))
	}
	project := filepath.Join(h.home, "work", "app")
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{project: map[string]any{"hasTrustDialogAccepted": true}}})
	h.write(filepath.Join(project, ".claude", "settings.json"), map[string]any{"hooks": hooksOf("SessionStart", "", command("echo hi"))})
	agent, _ := h.scan()
	if !agent.Truncated {
		t.Fatal("the skills should exceed the scope cap")
	}
	if len(byEvent(agent, "SessionStart")) != 1 {
		t.Fatalf("the project's settings were crowded out: %d scopes", len(agent.Scopes))
	}
}

// A skill whose last hook is removed keeps its scope, now empty, so the hook
// is withdrawn instead of kept as unseen.
func TestEmptiedSkillKeepsItsScope(t *testing.T) {
	h := newHookHome(t)
	path := h.write(filepath.Join(h.base, "skills", "deploy", "SKILL.md"), skillFile("PreToolUse", "echo check"))
	agent, _ := h.scan()
	pre := byEvent(agent, "PreToolUse")
	if len(pre) != 1 {
		t.Fatalf("%+v", agent.Hooks)
	}
	scope := pre[0].ScopeID
	h.write(path, []byte("---\nname: deploy\ndescription: Deploy things\n---\nBody\n"))
	agent, result := h.scan()
	if result.Status != StatusComplete || len(agent.Hooks) != 0 || scopeOf(agent, scope).Status != StatusComplete {
		t.Fatalf("result %+v scopes %+v", result, agent.Scopes)
	}
}

// Skill and subagent bounds leave the coverage verdict standing: they never
// hold a device-wide handler.
func TestSkillBoundsKeepTheCoverageVerdict(t *testing.T) {
	h := newHookHome(t)
	for i := range maxFrontmatterFiles + 1 {
		h.write(filepath.Join(h.base, "skills", fmt.Sprintf("s%03d", i), "SKILL.md"), []byte("---\nname: s\n---\n"))
	}
	agent, _ := h.scan()
	if !agent.Truncated || agent.KontextHooks.State != "missing" {
		t.Fatalf("truncated %v coverage %+v", agent.Truncated, agent.KontextHooks)
	}
}

// A project at the home folder doesn't read the user's skills twice.
func TestHomeProjectReadsSkillsOnce(t *testing.T) {
	h := newHookHome(t)
	h.write(filepath.Join(h.base, "skills", "deploy", "SKILL.md"), skillFile("PreToolUse", "echo check"))
	h.write(filepath.Join(h.home, ".claude.json"), map[string]any{"projects": map[string]any{h.home: map[string]any{"hasTrustDialogAccepted": true}}})
	agent, _ := h.scan()
	if got := len(byEvent(agent, "PreToolUse")); got != 1 {
		t.Fatalf("%d records", got)
	}
	ids := map[string]bool{}
	for _, scope := range agent.Scopes {
		if ids[scope.ID] {
			t.Fatalf("duplicate scope %s", scope.ID)
		}
		ids[scope.ID] = true
	}
}

// A SKILL.md at the top of a skills folder isn't read, so the scan says so.
func TestTopLevelSkillFileLeavesTheScanPartial(t *testing.T) {
	h := newHookHome(t)
	h.installPlugin("formatter@acme", nil, map[string]any{})
	dir := filepath.Join(h.base, "plugins/cache", "formatter", "1.4.0")
	h.write(filepath.Join(dir, "skills", "SKILL.md"), skillFile("Stop", "echo stop"))
	if _, result := h.scan(); result.Status != StatusPartial || !slices.Contains(result.Reasons, ReasonUnsupportedFormat) {
		t.Fatalf("%+v", result)
	}
}

// Plugin skills are read after every plugin's own hooks, so they can't
// crowd a later plugin's hooks out of the scope cap.
func TestPluginSkillsComeAfterPluginHooks(t *testing.T) {
	h := newHookHome(t)
	plugins := map[string]any{}
	for _, name := range []string{"aaa", "bbb", "zzz"} {
		dir := filepath.Join(h.base, "plugins/cache", name, "1.0.0")
		h.write(filepath.Join(dir, ".claude-plugin/plugin.json"), map[string]any{"name": name, "version": "1.0.0"})
		h.write(filepath.Join(dir, "hooks/hooks.json"), map[string]any{"hooks": hooksOf("SessionStart", "", command("echo "+name))})
		if name != "zzz" {
			for i := range maxFrontmatterFiles {
				h.write(filepath.Join(dir, "skills", fmt.Sprintf("s%03d", i), "SKILL.md"), skillFile("Stop", "echo stop"))
			}
		}
		plugins[name+"@acme"] = []any{map[string]any{"installPath": dir}}
	}
	h.write(filepath.Join(h.base, "plugins/installed_plugins.json"), map[string]any{"plugins": plugins})
	agent, _ := h.scan()
	if !agent.Truncated {
		t.Fatal("the skills should exceed the scope cap")
	}
	if got := len(byEvent(agent, "SessionStart")); got != 3 {
		t.Fatalf("%d plugin hooks read", got)
	}
}

const maxPairsForTest = 256

func wideMapping(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "k%d: v\n", i)
	}
	return b.String()
}
