package agentauthority

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/pkg/agentauthority/readers"
)

// Skills and subagents with hooks are scopes of their own; those without
// list nothing.
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
	kinds := map[string]int{}
	for _, scope := range agent.Scopes {
		kinds[scope.Kind]++
	}
	if kinds[HookScopeSkill] != 1 || kinds[HookScopeSubagent] != 1 {
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
	for _, r := range agent.Hooks {
		if r.Summary != nil && strings.Contains(*r.Summary, "FAKEhunter2") {
			t.Fatalf("summary %q", *r.Summary)
		}
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
