package antigravitymanaged

import (
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hermetic"
)

// Ways the installed file can fail, each pinned below:
//   - a hook whose binary is gone exits non-zero, and Antigravity blocks every
//     tool call on a failing PreToolUse hook (its plugin docs say it fails open;
//     measured on 2.29.0 it does not)
//   - a file event in the wrong shape: tool events need a matcher group, the rest
//     a flat list, and Antigravity skips what it cannot read
//   - someone's own hook in the same file is lost or rewritten
//   - a hook switched off with "enabled": false still counts as installed
//   - a binary path with spaces breaks the command
//   - an admin's command that merely contains the Kontext path counts as ours
func TestMergeWritesEveryEventInTheShapeAntigravityReads(t *testing.T) {
	hermetic.NotOnWindows(t, "ENG-1001", "Antigravity's hooks aren't written on Windows yet")
	t.Parallel()
	settings := map[string]any{}
	if err := MergeManagedHooks(settings, "/opt/homebrew/bin/kontext"); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	var file map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	group := file[HookName]
	for _, event := range Events {
		if event.Grouped {
			var groups []struct {
				Matcher string `json:"matcher"`
				Hooks   []struct {
					Type, Command string
					Timeout       int
				} `json:"hooks"`
			}
			if err := json.Unmarshal(group[event.Antigravity], &groups); err != nil {
				t.Fatalf("%s: %v", event.Antigravity, err)
			}
			if len(groups) != 1 || groups[0].Matcher != "*" || len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Timeout <= 0 {
				t.Fatalf("%s = %s", event.Antigravity, group[event.Antigravity])
			}
			continue
		}
		var handlers []struct {
			Type, Command string
			Timeout       int
		}
		if err := json.Unmarshal(group[event.Antigravity], &handlers); err != nil {
			t.Fatalf("%s must be flat: %v", event.Antigravity, err)
		}
		if len(handlers) != 1 || !strings.Contains(handlers[0].Command, "'"+event.Alias+"'") {
			t.Fatalf("%s = %s", event.Antigravity, group[event.Antigravity])
		}
	}
	binary, err := ValidateInstalled(raw)
	if err != nil || binary != "/opt/homebrew/bin/kontext" {
		t.Fatalf("validate = %q, %v", binary, err)
	}
}

func TestMergeAndRemoveKeepOtherHooks(t *testing.T) {
	hermetic.NotOnWindows(t, "ENG-1001", "Antigravity's hooks aren't written on Windows yet")
	t.Parallel()
	mine := map[string]any{"PreToolUse": []any{map[string]any{"matcher": "run_command", "hooks": []any{map[string]any{"command": "./audit.sh"}}}}}
	settings := map[string]any{"safety-gate": mine}
	if err := MergeManagedHooks(settings, "/usr/local/bin/kontext"); err != nil {
		t.Fatal(err)
	}
	if err := MergeManagedHooks(settings, "/opt/homebrew/bin/kontext"); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(settings)
	if binary, err := ValidateInstalled(raw); err != nil || binary != "/opt/homebrew/bin/kontext" {
		t.Fatalf("a moved binary must replace the old entries: %q, %v", binary, err)
	}
	if strings.Contains(string(raw), "/usr/local/bin/kontext") {
		t.Fatalf("stale binary left behind: %s", raw)
	}
	if !strings.Contains(string(raw), "./audit.sh") {
		t.Fatalf("someone's own hook was lost: %s", raw)
	}
	RemoveManagedHooks(settings)
	if _, ours := settings[HookName]; ours || settings["safety-gate"] == nil {
		t.Fatalf("after remove: %#v", settings)
	}
	RemoveManagedHooks(settings)
	if len(settings) != 1 {
		t.Fatalf("second remove changed the file: %#v", settings)
	}
}

func TestValidateInstalledFindsProblems(t *testing.T) {
	t.Parallel()
	valid := func() map[string]any {
		settings := map[string]any{}
		if err := MergeManagedHooks(settings, "/opt/homebrew/bin/kontext"); err != nil {
			t.Fatal(err)
		}
		return settings
	}
	if _, err := ValidateInstalled([]byte(`not json`)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed = %v", err)
	}
	if _, err := ValidateInstalled([]byte(`{}`)); err == nil || errors.Is(err, ErrMalformed) {
		t.Fatalf("absent group = %v", err)
	}
	if _, err := ValidateInstalled([]byte(`{"kontext":"nope"}`)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("group of the wrong shape = %v", err)
	}
	disabled := valid()
	disabled[HookName].(map[string]any)["enabled"] = false
	raw, _ := json.Marshal(disabled)
	if _, err := ValidateInstalled(raw); err == nil || !strings.Contains(err.Error(), "switched off") {
		t.Fatalf("disabled = %v", err)
	}
	for _, event := range Events {
		missing := valid()
		delete(missing[HookName].(map[string]any), event.Antigravity)
		raw, _ := json.Marshal(missing)
		if _, err := ValidateInstalled(raw); err == nil || !strings.Contains(err.Error(), event.Antigravity) {
			t.Fatalf("missing %s = %v", event.Antigravity, err)
		}
	}
	foreign := valid()
	foreign[HookName].(map[string]any)["Stop"] = []any{map[string]any{"command": "audit;/opt/homebrew/bin/kontext hook --agent 'antigravity' 'stop' || exit 0", "timeout": 20}}
	raw, _ = json.Marshal(foreign)
	if _, err := ValidateInstalled(raw); err == nil || !strings.Contains(err.Error(), "Stop") {
		t.Fatalf("foreign command = %v", err)
	}
}

func TestHookCommandParsesBack(t *testing.T) {
	hermetic.NotOnWindows(t, "ENG-1001", "Antigravity's hooks aren't written on Windows yet")
	t.Parallel()
	for _, binary := range []string{"/usr/local/bin/kontext", "/Applications/Kontext (Dev)/kontext"} {
		command := hookCommand(binary, "pre-tool-use")
		got, alias, ok := parseHookCommand(command)
		if !ok || got != binary || alias != "pre-tool-use" {
			t.Errorf("%s parsed as %q %q %v", command, got, alias, ok)
		}
	}
	for _, command := range []string{
		"/usr/local/bin/kontext hook --agent cursor pre-tool-use || exit 0",
		"relative/kontext hook --agent antigravity pre-tool-use || exit 0",
		"/usr/local/bin/kontext hook --agent antigravity pre-tool-use",
		"/usr/local/bin/other hook --agent antigravity pre-tool-use || exit 0",
	} {
		if _, _, ok := parseHookCommand(command); ok {
			t.Errorf("%q must not count as Kontext's", command)
		}
	}
}

// A failing PreToolUse hook blocks the tool. An uninstalled Kontext must leave
// nothing that stops the agent, so the command itself has to survive it: run it
// through the shell Antigravity uses.
func TestHookCommandPassesWhenTheBinaryIsGone(t *testing.T) {
	hermetic.NotOnWindows(t, "ENG-1001", "Antigravity's hooks aren't written on Windows yet")
	t.Parallel()
	gone := filepath.Join(t.TempDir(), "kontext")
	out, err := exec.Command("sh", "-c", hookCommand(gone, "pre-tool-use")).Output()
	if err != nil {
		t.Fatalf("a missing binary must exit 0: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("stdout = %q; empty stdout is Antigravity's no-decision answer", out)
	}
}

func TestUserHooksPath(t *testing.T) {
	hermetic.NotOnWindows(t, "ENG-1001", "Antigravity's hooks aren't written on Windows yet")
	t.Parallel()
	if got := UserHooksPath("/Users/dev"); got != "/Users/dev/.gemini/config/hooks.json" {
		t.Fatalf("path = %q", got)
	}
}
