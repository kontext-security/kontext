package codexmanaged

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

const testBinary = "/opt/homebrew/bin/kontext"

func decode(t *testing.T, raw string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func eventGroups(t *testing.T, settings map[string]any, event string) []any {
	t.Helper()
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		t.Fatalf("hooks missing or not an object: %T", settings["hooks"])
	}
	groups, ok := hooks[event].([]any)
	if !ok {
		t.Fatalf("event %s missing or not a list: %T", event, hooks[event])
	}
	return groups
}

func TestMergeManagedHooksIntoEmptySettings(t *testing.T) {
	settings := map[string]any{}
	if err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatalf("MergeManagedHooks() error = %v", err)
	}

	for _, event := range SupportedEvents {
		groups := eventGroups(t, settings, event.Name.String())
		if len(groups) != 1 {
			t.Fatalf("%s groups = %d, want 1", event.Name, len(groups))
		}
		handler := groups[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
		wantCommand := "'" + testBinary + "' hook --agent 'codex' '" + event.Alias + "'"
		if handler["command"] != wantCommand {
			t.Fatalf("%s command = %q, want %q", event.Name, handler["command"], wantCommand)
		}
		if _, present := handler["async"]; present {
			t.Fatalf("%s handler contains async: %v", event.Name, handler)
		}
	}

	data, err := json.Marshal(map[string]any{"hooks": settings["hooks"]})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data, testBinary); err != nil {
		t.Fatalf("merged hooks fail Validate: %v", err)
	}
}

func TestMergeManagedHooksPreservesForeignContent(t *testing.T) {
	settings := decode(t, `{
		"telemetry": {"enabled": true},
		"hooks": {
			"PreToolUse": [
				{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/other-tool check"}]}
			],
			"Stop": [
				{"hooks": [{"type": "command", "command": "say done"}]}
			]
		},
		"unknownKey": 42
	}`)

	if err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}

	if settings["unknownKey"] != float64(42) {
		t.Fatalf("unknownKey clobbered: %v", settings["unknownKey"])
	}
	if _, ok := settings["telemetry"].(map[string]any); !ok {
		t.Fatal("telemetry clobbered")
	}

	groups := eventGroups(t, settings, "PreToolUse")
	if len(groups) != 2 {
		t.Fatalf("PreToolUse groups = %d, want foreign + ours", len(groups))
	}
	if groups[0].(map[string]any)["matcher"] != "Bash" {
		t.Fatalf("foreign group reordered or modified: %v", groups[0])
	}
	stop := eventGroups(t, settings, "Stop")
	if len(stop) != 2 {
		t.Fatalf("Stop groups = %d, want foreign + ours", len(stop))
	}
	if stop[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"] != "say done" {
		t.Fatalf("foreign Stop hook reordered or modified: %v", stop[0])
	}
}

func TestMergeManagedHooksReplacesStaleBinaryPath(t *testing.T) {
	settings := decode(t, `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "", "hooks": [{"type": "command", "command": "'/Applications/Kontext CLI/kontext' hook --agent 'codex' 'pre-tool-use'", "timeout": 20}]}
			]
		}
	}`)

	if err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}

	groups := eventGroups(t, settings, "PreToolUse")
	if len(groups) != 1 {
		t.Fatalf("PreToolUse groups = %d, want stale entry replaced, not duplicated", len(groups))
	}
	handler := groups[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if !strings.Contains(handler["command"].(string), testBinary) {
		t.Fatalf("stale binary path not replaced: %v", handler["command"])
	}
}

func TestMergeManagedHooksIsIdempotent(t *testing.T) {
	settings := map[string]any{}
	if err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}
	first, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("double merge is not a fixpoint:\n%s\n%s", first, second)
	}
}

func TestRemoveManagedHooksLeavesForeignContent(t *testing.T) {
	settings := map[string]any{
		"telemetry": map[string]any{"enabled": true},
	}
	if err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}
	hooks := settings["hooks"].(map[string]any)
	pre := hooks["PreToolUse"].([]any)
	hooks["PreToolUse"] = append(pre, map[string]any{
		"matcher": "Edit",
		"hooks":   []any{map[string]any{"type": "command", "command": "lint-check"}},
	})

	if err := RemoveManagedHooks(settings); err != nil {
		t.Fatal(err)
	}

	hooks = settings["hooks"].(map[string]any)
	for _, event := range SupportedEvents {
		if event.Name.String() == "PreToolUse" {
			continue
		}
		if _, present := hooks[event.Name.String()]; present {
			t.Fatalf("%s not pruned after removal", event.Name)
		}
	}
	pre = hooks["PreToolUse"].([]any)
	if len(pre) != 1 || pre[0].(map[string]any)["matcher"] != "Edit" {
		t.Fatalf("foreign PreToolUse hook lost: %v", pre)
	}
	if _, ok := settings["telemetry"]; !ok {
		t.Fatal("telemetry clobbered by removal")
	}
}

func TestRemoveManagedHooksDropsEmptyHooksKey(t *testing.T) {
	settings := map[string]any{}
	if err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}
	if err := RemoveManagedHooks(settings); err != nil {
		t.Fatal(err)
	}
	if _, present := settings["hooks"]; present {
		t.Fatalf("empty hooks key left behind: %v", settings["hooks"])
	}
}

func TestIsManagedHookCommand(t *testing.T) {
	cases := []struct {
		command string
		want    bool
	}{
		{"'/usr/local/bin/kontext' hook --agent 'codex' 'pre-tool-use'", true},
		{"'/Users/o'\\''brien/bin/kontext' hook --agent 'codex' 'pre-tool-use'", true},
		{"'/Applications/Kontext CLI/kontext' hook --agent 'codex' 'session-start'", true},
		{"'/opt/homebrew/bin/kontext' hook --agent codex user-prompt-submit", true},
		{"'/opt/homebrew/bin/kontext' hook --agent codex stop", true},
		{"'/Applications/Kontext CLI/kontext' hook --agent 'codex' 'post-tool-use-failure'", false},
		{"'/Applications/Kontext CLI/kontext' hook --agent 'codex' 'session-end'", false},
		{"'/usr/local/bin/kontext' hook --agent 'codex' 'post-tool-use' --mode observe", false},
		{"'/usr/local/bin/kontext' hook 'pre-tool-use'", false},
		{"'/usr/local/bin/kontext' hook --agent 'claude' 'pre-tool-use'", false},
		{"kontext guard hook claude-code", false},
		{"/usr/local/bin/other-tool hook --agent codex pre-tool-use", false},
		{"/usr/local/bin/not-kontext hook --agent codex pre-tool-use", false},
		{"say done", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsManagedHookCommand(tc.command); got != tc.want {
			t.Errorf("IsManagedHookCommand(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}
}

func TestValidateInstalledAcceptsStableBinaryAndRejectsIncompleteHooks(t *testing.T) {
	data, err := TemplateJSON("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	binary, err := ValidateInstalled(data)
	if err != nil {
		t.Fatalf("ValidateInstalled() error = %v", err)
	}
	if binary != "/opt/homebrew/bin/kontext" {
		t.Fatalf("ValidateInstalled() binary = %q", binary)
	}

	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	delete(settings["hooks"].(map[string]any), hook.HookStop.String())
	broken, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateInstalled(broken); err == nil || !strings.Contains(err.Error(), "Stop hook missing") {
		t.Fatalf("ValidateInstalled() error = %v, want missing Stop hook", err)
	}

	data, err = TemplateJSON("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	stop := settings["hooks"].(map[string]any)[hook.HookStop.String()].([]any)
	stop[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"] = "'/opt/homebrew/bin/kontext' hook --agent 'codex' 'pre-tool-use'"
	wrongAlias, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateInstalled(wrongAlias); err == nil || !strings.Contains(err.Error(), "Stop hook uses") {
		t.Fatalf("ValidateInstalled() error = %v, want wrong alias", err)
	}
}

func TestUserHooksPathCreatesCodexDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	path, err := UserHooksPath()
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(home, ".codex", "hooks.json") {
		t.Fatalf("UserHooksPath() = %q", path)
	}
	if _, err := os.Stat(filepath.Join(home, ".codex")); err != nil {
		t.Fatalf(".codex dir missing: %v", err)
	}
}
