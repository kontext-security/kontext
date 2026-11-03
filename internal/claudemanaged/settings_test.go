package claudemanaged

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/profile"
	"github.com/kontext-security/kontext/internal/tooloutput"
)

// The rule names the directory the daemon saves outputs in as text, and nothing
// connects the two. Moving profile.Root has to move the rule in the same change,
// or reading a saved output back starts to ask for permission again.
func TestSavedOutputReadRuleNamesTheDaemonsSaveDirectory(t *testing.T) {
	home := t.TempDir()
	hermetic.SetHome(t, home)
	t.Setenv(profile.EnvRoot, "")

	root, err := filepath.Rel(home, profile.Root())
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("Read(~/%s/**/%s/tool-output/**)", filepath.ToSlash(root), profile.ManagedObserveDir)
	if SavedOutputReadRule != want {
		t.Fatalf("SavedOutputReadRule = %q, want %q", SavedOutputReadRule, want)
	}

	profileDir, err := profile.Dir("work")
	if err != nil {
		t.Fatal(err)
	}
	for _, base := range []string{profile.Root(), profileDir} {
		dbPath := filepath.Join(base, profile.ManagedObserveDir, profile.ManagedObserveDB)
		saved, err := filepath.Rel(profile.Root(), tooloutput.DefaultDirForDB(dbPath))
		if err != nil {
			t.Fatal(err)
		}
		slashed := filepath.ToSlash(saved)
		if slashed == ".." || strings.HasPrefix(slashed, "../") || !strings.HasSuffix("/"+slashed, "/"+profile.ManagedObserveDir+"/tool-output") {
			t.Fatalf("outputs for %s are saved in %q, which the rule doesn't name", dbPath, saved)
		}
	}
}

func TestValidateEquivalentCommandQuoting(t *testing.T) {
	t.Parallel()
	binary := "/Users/test/Library/Application Support/KontextManagement/runtime/bin/kontext"
	for _, format := range []string{"%s 'hook' '%s'", "%s \"hook\" \"%s\"", "%s\t hook   %s"} {
		t.Run(format, func(t *testing.T) {
			settings := Template(binary)
			for _, event := range SupportedEvents {
				settings.Hooks[event.Name.String()][0].Hooks[0].Command = fmt.Sprintf(format, agenthooks.ShellQuote(binary), event.Alias)
			}
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(data, binary); err != nil {
				t.Fatal(err)
			}
			if got, ok := ManagedObserveHookBinary(data); !ok || got != binary {
				t.Fatalf("ManagedObserveHookBinary = %q, %v", got, ok)
			}
		})
	}
}

func TestValidateCommandStillRequiresExactLiteralArguments(t *testing.T) {
	t.Parallel()
	binary := "/tmp/$BUILD/kontext"
	for _, command := range []string{
		`'/other/kontext' hook pre-tool-use`,
		`'/tmp/$BUILD/kontext' hook post-tool-use`,
		`'/tmp/$BUILD/kontext' hook pre-tool-use --mode observe`,
		`'/tmp/$BUILD/kontext' hook pre-tool-use; echo ok`,
		`'/tmp/$BUILD/kontext' hook pre-tool-use >/tmp/output`,
		"'/tmp/$BUILD/kontext'\nhook pre-tool-use",
		`"/tmp/$BUILD/kontext" hook pre-tool-use`,
		`'/tmp/$BUILD/kontext' 'hook pre-tool-use`,
	} {
		t.Run(command, func(t *testing.T) {
			settings := Template(binary)
			settings.Hooks["PreToolUse"][0].Hooks[0].Command = command
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatal(err)
			}
			if err := Validate(data, binary); err == nil {
				t.Fatal("invalid command passed validation")
			}
		})
	}
	data, err := TemplateJSON(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(data, binary); err != nil {
		t.Fatalf("quoted literal dollar sign: %v", err)
	}
}

func TestRecognizeLegacyDropInForUsageHookUpgrade(t *testing.T) {
	settings := Template("")
	delete(settings.Hooks, "UserPromptSubmit")
	delete(settings.Hooks, "Stop")
	delete(settings.Hooks, "SubagentStop")
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !IsManagedSettingsDropIn(data) {
		t.Fatal("must recognize our old settings so setup can add Stop")
	}
	if HasManagedObserveHooks(data) {
		t.Fatal("old hooks must not claim complete usage coverage")
	}
	settings.Hooks["PreCompact"] = settings.Hooks["SessionStart"]
	foreign, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if IsManagedSettingsDropIn(foreign) {
		t.Fatal("legacy settings with a foreign event must not be overwritten")
	}
}

func TestPromptHookIsRequiredAndLegacyDropInRemainsUpgradeable(t *testing.T) {
	settings := Template(testBinary)
	groups := settings.Hooks["UserPromptSubmit"]
	if len(groups) != 1 || len(groups[0].Hooks) != 1 || groups[0].Hooks[0].Async != nil {
		t.Fatalf("prompt must be captured before tools run: %+v", groups)
	}
	delete(settings.Hooks, "UserPromptSubmit")
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !IsManagedSettingsDropIn(data) || HasManagedObserveHooks(data) || Validate(data, testBinary) == nil {
		t.Fatal("legacy configuration must be recognized as ours but incomplete")
	}
	missing, binary := MissingRequiredEvents(data)
	if len(missing) != 1 || missing[0] != "UserPromptSubmit" || binary != testBinary {
		t.Fatalf("upgrade diagnosis = %v / %s", missing, binary)
	}
}

func TestTemplateIncludesManagedKontextHooks(t *testing.T) {
	t.Parallel()

	settings := Template("/opt/kontext/bin/kontext")
	if len(settings.Hooks) != len(SupportedEvents) {
		t.Fatalf("hooks count = %d, want %d", len(settings.Hooks), len(SupportedEvents))
	}
	if settings.AllowManagedHooksOnly != nil {
		t.Fatal("AllowManagedHooksOnly set, want omitted")
	}
	if settings.DisableAllHooks != nil {
		t.Fatal("DisableAllHooks set, want omitted")
	}
	// Saved outputs can be read back without a prompt; nothing else is allowed.
	if settings.Permissions == nil || !reflect.DeepEqual(settings.Permissions.Allow, []string{SavedOutputReadRule}) {
		t.Fatalf("Permissions = %+v, want only the saved-output read rule", settings.Permissions)
	}

	for _, event := range SupportedEvents {
		groups := settings.Hooks[event.Name.String()]
		if len(groups) != 1 {
			t.Fatalf("%s groups = %d, want 1", event.Name, len(groups))
		}
		if groups[0].Matcher != "" {
			t.Fatalf("%s matcher = %q, want empty", event.Name, groups[0].Matcher)
		}
		if len(groups[0].Hooks) != 1 {
			t.Fatalf("%s handlers = %d, want 1", event.Name, len(groups[0].Hooks))
		}
		handler := groups[0].Hooks[0]
		if handler.Type != "command" {
			t.Fatalf("%s handler type = %q, want command", event.Name, handler.Type)
		}
		wantCommand := "'/opt/kontext/bin/kontext' hook '" + event.Alias + "'"
		if handler.Command != wantCommand {
			t.Fatalf("%s command = %q, want %q", event.Name, handler.Command, wantCommand)
		}
		if len(handler.Args) != 0 {
			t.Fatalf("%s args = %q, want omitted", event.Name, handler.Args)
		}
		if handler.Timeout != DefaultHookTimeout {
			t.Fatalf("%s timeout = %d, want %d", event.Name, handler.Timeout, DefaultHookTimeout)
		}
		if event.Async {
			if handler.Async == nil || !*handler.Async {
				t.Fatalf("%s async = %v, want true", event.Name, handler.Async)
			}
		} else if handler.Async != nil {
			t.Fatalf("%s async = %v, want omitted", event.Name, *handler.Async)
		}
	}
}

func TestTemplateJSONUsesClaudeCommandForm(t *testing.T) {
	t.Parallel()

	data, err := TemplateJSON("/usr/local/bin/kontext")
	if err != nil {
		t.Fatalf("TemplateJSON() error = %v", err)
	}
	if !strings.Contains(string(data), "'/usr/local/bin/kontext' hook 'pre-tool-use'") {
		t.Fatalf("template does not include Claude command-form hook: %s", data)
	}

	var decoded Settings
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if err := Validate(data, "/usr/local/bin/kontext"); err != nil {
		t.Fatalf("Validate(template) error = %v", err)
	}
}

func TestTemplateJSONOnlyMarksLifecycleHooksAsync(t *testing.T) {
	t.Parallel()

	data, err := TemplateJSON("/usr/local/bin/kontext")
	if err != nil {
		t.Fatalf("TemplateJSON() error = %v", err)
	}

	var raw struct {
		Hooks map[string][]struct {
			Hooks []map[string]any `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	for _, event := range SupportedEvents {
		groups, ok := raw.Hooks[event.Name.String()]
		if !ok {
			t.Fatalf("%s hook missing", event.Name)
		}
		if len(groups) != 1 {
			t.Fatalf("%s groups = %d, want 1", event.Name, len(groups))
		}
		handlers := groups[0].Hooks
		if len(handlers) != 1 {
			t.Fatalf("%s handlers = %d, want 1", event.Name, len(handlers))
		}
		async, hasAsync := handlers[0]["async"]
		if event.Async {
			asyncBool, ok := async.(bool)
			if !hasAsync || !ok || !asyncBool {
				t.Fatalf("%s async = %v, want boolean true", event.Name, async)
			}
		} else if hasAsync {
			t.Fatalf("%s async emitted, want omitted", event.Name)
		}
	}
}

func TestTemplateTrimsKontextBinary(t *testing.T) {
	t.Parallel()

	settings := Template(" /usr/local/bin/kontext ")
	handler := settings.Hooks["PreToolUse"][0].Hooks[0]
	if handler.Command != "'/usr/local/bin/kontext' hook 'pre-tool-use'" {
		t.Fatalf("command = %q, want trimmed command form", handler.Command)
	}
}

// The files Claude Code reads on each OS, spelled out. Each OS checks its own
// row when its tests run. CI runs no Go tests on macOS, so platform's
// TestClaudeManagedDirOn pins that folder on Linux as well.
func TestManagedSettingsPaths(t *testing.T) {
	t.Parallel()

	want, ok := map[string]struct{ file, dropIn string }{
		"darwin": {
			"/Library/Application Support/ClaudeCode/managed-settings.json",
			"/Library/Application Support/ClaudeCode/managed-settings.d/20-kontext.json",
		},
		"linux": {
			"/etc/claude-code/managed-settings.json",
			"/etc/claude-code/managed-settings.d/20-kontext.json",
		},
		"windows": {
			`C:\Program Files\ClaudeCode\managed-settings.json`,
			`C:\Program Files\ClaudeCode\managed-settings.d\20-kontext.json`,
		},
	}[runtime.GOOS]
	if !ok {
		t.Skipf("no managed settings path pinned for %s", runtime.GOOS)
	}
	if got := DefaultManagedSettingsPath(); got != want.file {
		t.Errorf("DefaultManagedSettingsPath() = %q, want %q", got, want.file)
	}
	if got := DefaultManagedSettingsDropInPath(); got != want.dropIn {
		t.Errorf("DefaultManagedSettingsDropInPath() = %q, want %q", got, want.dropIn)
	}
}

func TestValidateRejectsInvalidManagedSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(Settings) Settings
		wantErr string
	}{
		{
			name: "missing event",
			mutate: func(settings Settings) Settings {
				delete(settings.Hooks, "SessionEnd")
				return settings
			},
			wantErr: "SessionEnd hook missing",
		},
		{
			name: "unrelated command mentions kontext hook",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Hooks = append(settings.Hooks["PreToolUse"][0].Hooks, Handler{
					Type:    "command",
					Command: `/bin/echo "kontext hook pre-tool-use"`,
				})
				return settings
			},
		},
		{
			name: "legacy exec args",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Hooks[0].Args = []string{"hook", "pre-tool-use"}
				return settings
			},
			wantErr: "PreToolUse Kontext handler args must be omitted",
		},
		{
			name: "missing lifecycle async",
			mutate: func(settings Settings) Settings {
				settings.Hooks["SessionStart"][0].Hooks[0].Async = nil
				return settings
			},
			wantErr: "SessionStart Kontext handler async must be true",
		},
		{
			name: "false lifecycle async",
			mutate: func(settings Settings) Settings {
				value := false
				settings.Hooks["SessionEnd"][0].Hooks[0].Async = &value
				return settings
			},
			wantErr: "SessionEnd Kontext handler async must be true",
		},
		{
			name: "async decision hook",
			mutate: func(settings Settings) Settings {
				value := true
				settings.Hooks["PreToolUse"][0].Hooks[0].Async = &value
				return settings
			},
			wantErr: "PreToolUse Kontext handler async must be omitted",
		},
		{
			name: "restrictive matcher",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Matcher = "Bash"
				return settings
			},
			wantErr: "PreToolUse Kontext command hook uses matcher \"Bash\"",
		},
		{
			name: "first restrictive matcher wins",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"] = []MatcherGroup{
					{
						Matcher: "Bash",
						Hooks: []Handler{{
							Type:    "command",
							Command: "'/usr/local/bin/kontext' hook 'pre-tool-use'",
						}},
					},
					{
						Matcher: "Git",
						Hooks: []Handler{{
							Type:    "command",
							Command: "'/usr/local/bin/kontext' hook 'pre-tool-use'",
						}},
					},
				}
				return settings
			},
			wantErr: "PreToolUse Kontext command hook uses matcher \"Bash\"",
		},
		{
			name: "wrong handler type",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreToolUse"][0].Hooks[0].Type = "prompt"
				return settings
			},
			wantErr: "PreToolUse Kontext handler type = \"prompt\", want command",
		},
		{
			name: "disable all hooks",
			mutate: func(settings Settings) Settings {
				value := true
				settings.DisableAllHooks = &value
				return settings
			},
			wantErr: "disableAllHooks must not be true",
		},
		{
			name: "managed hooks only allowed",
			mutate: func(settings Settings) Settings {
				value := true
				settings.AllowManagedHooksOnly = &value
				return settings
			},
		},
		{
			name: "unrelated settings ignored",
			mutate: func(settings Settings) Settings {
				settings.Hooks["PreCompact"] = []MatcherGroup{{
					Matcher: "",
					Hooks: []Handler{{
						Type:    "command",
						Command: "/bin/echo",
					}},
				}}
				return settings
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			settings := tt.mutate(Template("/usr/local/bin/kontext"))
			data, err := json.Marshal(settings)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}

			err = Validate(data, "/usr/local/bin/kontext")
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() error = nil, want non-nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestParseEventAlias(t *testing.T) {
	t.Parallel()

	got, ok := ParseEventAlias("pre-tool-use")
	if !ok {
		t.Fatal("ParseEventAlias() ok = false")
	}
	if got.String() != "PreToolUse" {
		t.Fatalf("ParseEventAlias() = %q, want PreToolUse", got)
	}
	if _, ok := ParseEventAlias("pretooluse"); ok {
		t.Fatal("ParseEventAlias(pretooluse) ok = true, want false")
	}
}

func TestIsManagedSettingsDropIn(t *testing.T) {
	t.Parallel()

	ours, err := TemplateJSON("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	stale, err := TemplateJSON("/old/Cellar/x/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	missingAsyncSettings := Template("/opt/homebrew/bin/kontext")
	missingAsyncSettings.Hooks["SessionStart"][0].Hooks[0].Async = nil
	missingAsync, err := json.Marshal(missingAsyncSettings)
	if err != nil {
		t.Fatal(err)
	}
	// Drop-ins written before tool output compaction carry hooks alone.
	hooksOnlySettings := Template("/opt/homebrew/bin/kontext")
	hooksOnlySettings.Permissions = nil
	hooksOnly, err := json.Marshal(hooksOnlySettings)
	if err != nil {
		t.Fatal(err)
	}
	widerSettings := Template("/opt/homebrew/bin/kontext")
	widerSettings.Permissions.Allow = append(widerSettings.Permissions.Allow, "Read(~/**)")
	wider, err := json.Marshal(widerSettings)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		data string
		want bool
	}{
		{"our template", string(ours), true},
		{"stale binary path still ours", string(stale), true},
		{"hooks-only template still ours", string(hooksOnly), true},
		{"wider permissions", string(wider), false},
		{"permissions alone", `{"permissions":{"allow":["` + SavedOutputReadRule + `"]}}`, false},
		{"ours plus foreign top-level key", `{"hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"'/opt/homebrew/bin/kontext' hook 'pre-tool-use'"}]}]},"permissions":{"deny":["x"]}}`, false},
		{"partial managed hook file", `{"hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"'/opt/homebrew/bin/kontext' hook 'pre-tool-use'","timeout":20}]}]}}`, false},
		{"non canonical matcher", strings.Replace(string(ours), `"matcher": ""`, `"matcher": "*"`, 1), false},
		{"non canonical timeout", strings.Replace(string(ours), `"timeout": 20`, `"timeout": 5`, 1), false},
		{"missing lifecycle async", string(missingAsync), false},
		{"extra event", strings.Replace(string(ours), `"hooks": {`, `"hooks": {"PreCompact":[{"matcher":"","hooks":[{"type":"command","command":"'/opt/homebrew/bin/kontext' hook 'pre-tool-use'","timeout":20}]}],`, 1), false},
		{"foreign hook command", `{"hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"/opt/other/tool run"}]}]}}`, false},
		{"no hooks", `{"hooks":{}}`, false},
		{"empty object", `{}`, false},
		{"garbage", `not json`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsManagedSettingsDropIn([]byte(tc.data)); got != tc.want {
				t.Fatalf("IsManagedSettingsDropIn(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestHasManagedObserveHooksRejectsDisabledHooks(t *testing.T) {
	t.Parallel()

	settings := Template("/opt/homebrew/bin/kontext")
	disabled := true
	settings.DisableAllHooks = &disabled
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}

	if HasManagedObserveHooks(data) {
		t.Fatal("HasManagedObserveHooks() = true with disableAllHooks")
	}
	if !DisablesAllHooks(data) {
		t.Fatal("DisablesAllHooks() = false with disableAllHooks")
	}
}

func TestHasManagedObserveHooksAllowsRootManagedSettingsFields(t *testing.T) {
	t.Parallel()

	settings := Template("/opt/homebrew/bin/kontext")
	allow := true
	settings.AllowManagedHooksOnly = &allow
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}

	if !HasManagedObserveHooks(data) {
		t.Fatal("HasManagedObserveHooks() = false for root managed settings")
	}
}
