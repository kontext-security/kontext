package claudemanaged

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
	warnings, err := MergeManagedHooks(settings, testBinary)
	if err != nil {
		t.Fatalf("MergeManagedHooks() error = %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}

	for _, event := range SupportedEvents {
		groups := eventGroups(t, settings, event.Name.String())
		if len(groups) != 1 {
			t.Fatalf("%s groups = %d, want 1", event.Name, len(groups))
		}
	}

	data, err := json.Marshal(map[string]any{"hooks": settings["hooks"]})
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data, testBinary); err != nil {
		t.Fatalf("merged settings fail Validate: %v", err)
	}
}

func TestMergeAddsPromptCaptureAndPreservesForeignPromptHook(t *testing.T) {
	settings := decode(t, `{"hooks":{"UserPromptSubmit":[{"hooks":[{"type":"command","command":"my-prompt-helper"}]}]},"permissions":{"allow":["Bash(ls:*)"]}}`)
	for range 2 {
		if _, err := MergeManagedHooks(settings, testBinary); err != nil {
			t.Fatal(err)
		}
	}
	groups := eventGroups(t, settings, "UserPromptSubmit")
	data, err := json.Marshal(groups)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || strings.Count(string(data), "my-prompt-helper") != 1 || strings.Count(string(data), "user-prompt-submit") != 1 {
		t.Fatalf("prompt upgrade lost or duplicated a hook: %s", data)
	}
	if _, ok := settings["permissions"]; !ok {
		t.Fatal("foreign permissions removed")
	}
}

func TestMergeManagedHooksMatchesTemplateShape(t *testing.T) {
	settings := map[string]any{}
	if _, err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(Template(testBinary).Hooks)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}

	for _, event := range SupportedEvents {
		name := event.Name.String()
		got := eventGroups(t, settings, name)
		if !reflect.DeepEqual(got, want[name]) {
			t.Fatalf("%s merged group = %#v, want %#v", name, got, want[name])
		}
	}
}

func TestMergeManagedHooksPreservesForeignContent(t *testing.T) {
	settings := decode(t, `{
		"permissions": {"allow": ["Bash(ls:*)"]},
		"env": {"FOO": "bar"},
		"hooks": {
			"PreToolUse": [
				{"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/other-tool check"}]}
			],
			"Notification": [
				{"matcher": "", "hooks": [{"type": "command", "command": "say done"}]}
			]
		},
		"unknownKey": 42
	}`)

	if _, err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}

	if settings["unknownKey"] != float64(42) {
		t.Fatalf("unknownKey clobbered: %v", settings["unknownKey"])
	}
	if _, ok := settings["permissions"].(map[string]any); !ok {
		t.Fatal("permissions clobbered")
	}

	groups := eventGroups(t, settings, "PreToolUse")
	if len(groups) != 2 {
		t.Fatalf("PreToolUse groups = %d, want foreign + ours", len(groups))
	}
	foreign := groups[0].(map[string]any)
	if foreign["matcher"] != "Bash" {
		t.Fatalf("foreign group reordered or modified: %v", foreign)
	}

	notification := eventGroups(t, settings, "Notification")
	if len(notification) != 1 {
		t.Fatalf("Notification groups = %d, want 1", len(notification))
	}
}

func TestMergeManagedHooksPreservesMalformedEventValues(t *testing.T) {
	settings := decode(t, `{
		"hooks": {
			"PreToolUse": "invalid"
		}
	}`)

	if _, err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}

	groups := eventGroups(t, settings, "PreToolUse")
	if len(groups) != 2 || groups[0] != "invalid" {
		t.Fatalf("PreToolUse groups = %#v, want malformed value plus managed group", groups)
	}

	if err := RemoveManagedHooks(settings); err != nil {
		t.Fatal(err)
	}
	groups = eventGroups(t, settings, "PreToolUse")
	if len(groups) != 1 || groups[0] != "invalid" {
		t.Fatalf("PreToolUse groups after remove = %#v, want malformed value preserved", groups)
	}
}

func TestMergeManagedHooksReplacesStaleBinaryPath(t *testing.T) {
	settings := decode(t, `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "", "hooks": [{"type": "command", "command": "'/Applications/Kontext CLI/kontext' hook 'pre-tool-use'", "timeout": 20}]}
			]
		}
	}`)

	if _, err := MergeManagedHooks(settings, testBinary); err != nil {
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

func TestMergeManagedHooksReplacesSplitCommandArgs(t *testing.T) {
	settings := decode(t, `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "", "hooks": [{"type": "command", "command": "/Applications/Kontext CLI/kontext", "args": ["hook", "pre-tool-use"], "timeout": 20}]}
			]
		}
	}`)

	if _, err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}

	groups := eventGroups(t, settings, "PreToolUse")
	if len(groups) != 1 {
		t.Fatalf("PreToolUse groups = %d, want split command entry replaced, not duplicated", len(groups))
	}
	handler := groups[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if _, present := handler["args"]; present {
		t.Fatalf("split command args were preserved on canonical handler: %v", handler)
	}
	if !strings.Contains(handler["command"].(string), testBinary) {
		t.Fatalf("split command path not replaced: %v", handler["command"])
	}
}

func TestMergeManagedHooksIsIdempotent(t *testing.T) {
	settings := map[string]any{}
	if _, err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}
	first, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeManagedHooks(settings, testBinary); err != nil {
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

func TestMergeManagedHooksWarnsOnDisableAllHooks(t *testing.T) {
	settings := decode(t, `{"disableAllHooks": true}`)
	warnings, err := MergeManagedHooks(settings, testBinary)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "disableAllHooks") {
		t.Fatalf("warnings = %v, want disableAllHooks warning", warnings)
	}
	if settings["disableAllHooks"] != true {
		t.Fatal("disableAllHooks was mutated")
	}
}

func TestMergeManagedHooksWarnsOnGuardHooksAndLeavesThem(t *testing.T) {
	settings := decode(t, `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "", "hooks": [{"type": "command", "command": "'/usr/local/bin/kontext' hook --agent claude --event pre-tool-use --mode observe"}]}
			]
		}
	}`)

	warnings, err := MergeManagedHooks(settings, testBinary)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "Guard") {
		t.Fatalf("warnings = %v, want guard-conflict warning", warnings)
	}

	groups := eventGroups(t, settings, "PreToolUse")
	if len(groups) != 2 {
		t.Fatalf("PreToolUse groups = %d, want guard hook + ours", len(groups))
	}
}

func TestMergeManagedHooksWarnsOnSplitArgsGuardHooks(t *testing.T) {
	settings := decode(t, `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "", "hooks": [{"type": "command", "command": "kontext", "args": ["hook", "--agent", "claude", "--event", "pre-tool-use", "--mode", "observe"]}]}
			]
		}
	}`)

	warnings, err := MergeManagedHooks(settings, testBinary)
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "Guard") {
		t.Fatalf("warnings = %v, want guard-conflict warning", warnings)
	}

	groups := eventGroups(t, settings, "PreToolUse")
	if len(groups) != 2 {
		t.Fatalf("PreToolUse groups = %d, want guard hook + ours", len(groups))
	}
}

func TestMergeManagedHooksRejectsNonObjectHooks(t *testing.T) {
	settings := decode(t, `{"hooks": ["weird"]}`)
	if _, err := MergeManagedHooks(settings, testBinary); err == nil {
		t.Fatal("expected error for non-object hooks, got nil")
	}
}

func TestRemoveManagedHooksLeavesForeignContent(t *testing.T) {
	settings := map[string]any{
		"permissions": map[string]any{"allow": []any{"Bash(ls:*)"}},
	}
	if _, err := MergeManagedHooks(settings, testBinary); err != nil {
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
	for _, event := range []string{"SessionStart", "PostToolUse", "SessionEnd"} {
		if _, present := hooks[event]; present {
			t.Fatalf("%s not pruned after removal", event)
		}
	}
	pre = hooks["PreToolUse"].([]any)
	if len(pre) != 1 || pre[0].(map[string]any)["matcher"] != "Edit" {
		t.Fatalf("foreign PreToolUse hook lost: %v", pre)
	}
	if _, ok := settings["permissions"]; !ok {
		t.Fatal("permissions clobbered by removal")
	}
}

func TestRemoveManagedHooksRemovesSplitCommandArgs(t *testing.T) {
	settings := decode(t, `{
		"hooks": {
			"PreToolUse": [
				{"matcher": "", "hooks": [
					{"type": "command", "command": "kontext", "args": ["hook", "pre-tool-use"]},
					{"type": "command", "command": "lint-check"}
				]}
			]
		}
	}`)

	if err := RemoveManagedHooks(settings); err != nil {
		t.Fatal(err)
	}

	groups := eventGroups(t, settings, "PreToolUse")
	if len(groups) != 1 {
		t.Fatalf("PreToolUse groups = %d, want one foreign group", len(groups))
	}
	handlers := groups[0].(map[string]any)["hooks"].([]any)
	if len(handlers) != 1 || handlers[0].(map[string]any)["command"] != "lint-check" {
		t.Fatalf("remaining handlers = %v, want only foreign handler", handlers)
	}
}

func TestRemoveManagedHooksDropsEmptyHooksKey(t *testing.T) {
	settings := map[string]any{}
	if _, err := MergeManagedHooks(settings, testBinary); err != nil {
		t.Fatal(err)
	}
	if err := RemoveManagedHooks(settings); err != nil {
		t.Fatal(err)
	}
	if _, present := settings["hooks"]; present {
		t.Fatalf("empty hooks key left behind: %v", settings["hooks"])
	}
}

func TestIsGuardHookCommand(t *testing.T) {
	cases := []struct {
		command string
		want    bool
	}{
		{"kontext guard hook claude-code", true},
		{"'/usr/local/bin/kontext' guard hook claude-code", true},
		{"'/usr/local/bin/kontext' hook --agent claude --event pre-tool-use --mode observe", true},
		// Managed-observe hooks must never match.
		{"'/usr/local/bin/kontext' hook 'pre-tool-use'", false},
		// --agent without --mode is not a guard hook.
		{"kontext hook --agent claude", false},
		{"say done", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsGuardHookCommand(tc.command); got != tc.want {
			t.Errorf("IsGuardHookCommand(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}
}

func TestIsManagedHookCommand(t *testing.T) {
	cases := []struct {
		command string
		want    bool
	}{
		{"'/usr/local/bin/kontext' hook 'pre-tool-use'", true},
		{"'/Users/o'\\''brien/bin/kontext' hook 'pre-tool-use'", true},
		{"'/Applications/Kontext CLI/kontext' hook 'pre-tool-use'", true},
		{"'/Users/dev/--tools/kontext' hook 'pre-tool-use'", true},
		{"'/opt/homebrew/bin/kontext' hook 'session-start'", true},
		{"/usr/local/bin/kontext hook session-end", true},
		{"'/usr/local/bin/kontext' hook 'unterminated", false},
		{`"/tmp/kon\text" hook pre-tool-use`, false},
		// Guard hooks must never match.
		{"'/usr/local/bin/kontext' hook --agent claude --event pre-tool-use --mode observe", false},
		{"kontext guard hook claude-code", false},
		// Foreign tools must never match.
		{"/usr/local/bin/other-tool hook pre-tool-use", false},
		{"/usr/local/bin/not-kontext hook pre-tool-use", false},
		{"my-kontext-helper hook session-end", false},
		{"say done", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsManagedHookCommand(tc.command); got != tc.want {
			t.Errorf("IsManagedHookCommand(%q) = %v, want %v", tc.command, got, tc.want)
		}
	}
}

func TestReadWriteUserSettingsPreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	// New files are created private.
	if err := WriteUserSettings(path, map[string]any{"a": float64(1)}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode = %v, want 0600", info.Mode().Perm())
	}

	// An existing file's (looser) mode is preserved, not tightened or loosened.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteUserSettings(path, map[string]any{"a": float64(2)}); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("rewritten file mode = %v, want 0644 preserved", info.Mode().Perm())
	}

	got, err := ReadUserSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, map[string]any{"a": float64(2)}) {
		t.Fatalf("round trip = %v", got)
	}
}

func TestWriteUserSettingsPreservesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target-settings.json")
	firstLink := filepath.Join(dir, "first-settings.json")
	link := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(target, []byte(`{"a":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, firstLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(firstLink, link); err != nil {
		t.Fatal(err)
	}

	if err := WriteUserSettings(link, map[string]any{"a": float64(2)}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("settings path is no longer a symlink: mode=%v", info.Mode())
	}
	firstInfo, err := os.Lstat(firstLink)
	if err != nil {
		t.Fatal(err)
	}
	if firstInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("intermediate settings path is no longer a symlink: mode=%v", firstInfo.Mode())
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"a": 2`) {
		t.Fatalf("target content = %s, want rewritten target", data)
	}
}

func TestReadUserSettingsMissingFileIsEmpty(t *testing.T) {
	got, err := ReadUserSettings(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("missing file settings = %v, want empty", got)
	}
}

func TestReadUserSettingsMalformedJSONFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadUserSettings(path); err == nil {
		t.Fatal("expected parse error, got nil")
	}
}

func TestBackupUserSettingsPreservesModeAndContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := BackupUserSettings(path, "kontext-setup"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var backup string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "kontext-setup-backup-") {
			backup = filepath.Join(dir, entry.Name())
		}
	}
	if backup == "" {
		t.Fatal("no backup file written")
	}
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("backup mode = %v, want original 0640", info.Mode().Perm())
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"a":1}` {
		t.Fatalf("backup content = %s", data)
	}

	// Missing file is a no-op.
	if err := BackupUserSettings(filepath.Join(dir, "absent.json"), "x"); err != nil {
		t.Fatal(err)
	}
}

func TestBackupUserSettingsDoesNotOverwriteExistingBackup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(`{"a":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := BackupUserSettings(path, "kontext-setup"); err != nil {
		t.Fatal(err)
	}
	if err := BackupUserSettings(path, "kontext-setup"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backups := 0
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "kontext-setup-backup-") {
			backups++
		}
	}
	if backups != 2 {
		t.Fatalf("backup count = %d, want 2", backups)
	}
}
