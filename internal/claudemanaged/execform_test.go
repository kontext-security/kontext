package claudemanaged

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/agenthooks"
)

// hostExecForm is ExecForm as this OS sets it. TestMain then pins the shell
// form, which the older tests here were written for, on every OS; the tests in
// this file choose the form themselves.
var hostExecForm = ExecForm

func TestMain(m *testing.M) {
	ExecForm = false
	os.Exit(m.Run())
}

// useForm sets the hook form for one test. Callers must not run in parallel.
func useForm(t *testing.T, exec bool) {
	t.Helper()
	old := ExecForm
	ExecForm = exec
	t.Cleanup(func() { ExecForm = old })
}

func TestExecFormIsTheWindowsDefault(t *testing.T) {
	if want := runtime.GOOS == "windows"; hostExecForm != want {
		t.Fatalf("ExecForm on %s = %v, want %v", runtime.GOOS, hostExecForm, want)
	}
}

// The handler bytes Claude Code reads, per form. The shell form is what macOS
// writes; Windows writes the exec form, which runs without a shell.
func TestTemplateHookForm(t *testing.T) {
	for _, tt := range []struct {
		name, binary string
		exec         bool
		pre, start   string
	}{
		{
			name: "shell form", binary: "/opt/homebrew/bin/kontext",
			pre:   `{"type":"command","command":"'/opt/homebrew/bin/kontext' hook 'pre-tool-use'","timeout":20}`,
			start: `{"type":"command","command":"'/opt/homebrew/bin/kontext' hook 'session-start'","timeout":20,"async":true}`,
		},
		{
			name: "exec form, Windows path with spaces", binary: `C:\Program Files\Kontext\kontext.exe`, exec: true,
			pre:   `{"type":"command","command":"C:\\Program Files\\Kontext\\kontext.exe","args":["hook","pre-tool-use"],"timeout":20}`,
			start: `{"type":"command","command":"C:\\Program Files\\Kontext\\kontext.exe","args":["hook","session-start"],"timeout":20,"async":true}`,
		},
		{
			name: "exec form, POSIX path", binary: "/opt/kontext/kontext", exec: true,
			pre:   `{"type":"command","command":"/opt/kontext/kontext","args":["hook","pre-tool-use"],"timeout":20}`,
			start: `{"type":"command","command":"/opt/kontext/kontext","args":["hook","session-start"],"timeout":20,"async":true}`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			useForm(t, tt.exec)
			data, err := TemplateJSON(tt.binary)
			if err != nil {
				t.Fatal(err)
			}
			var raw struct {
				Hooks map[string][]struct {
					Hooks []json.RawMessage `json:"hooks"`
				} `json:"hooks"`
			}
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			for event, want := range map[string]string{"PreToolUse": tt.pre, "SessionStart": tt.start} {
				if got := compact(t, raw.Hooks[event][0].Hooks[0]); got != want {
					t.Errorf("%s handler = %s, want %s", event, got, want)
				}
			}
			if strings.Contains(string(data), `"args"`) != tt.exec {
				t.Errorf("args present = %v, want %v:\n%s", !tt.exec, tt.exec, data)
			}
		})
	}
}

// Every reader recognises what Template writes in either form, including a
// Windows path without spaces and kontext.exe in another letter case, so a
// rerun finds nothing to change and removal finds every entry.
func TestHookFormRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		name, binary string
		exec         bool
	}{
		{"shell form", "/opt/homebrew/bin/kontext", false},
		{"exec form, Windows path with spaces", `C:\Program Files\Kontext\kontext.exe`, true},
		{"exec form, Windows path without spaces", `C:\Users\t\kontext.exe`, true},
		{"exec form, upper-case exe", `C:\Program Files\Kontext\KONTEXT.EXE`, true},
		{"exec form, POSIX path", "/opt/kontext/kontext", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			useForm(t, tt.exec)
			data, err := TemplateJSON(tt.binary)
			if err != nil {
				t.Fatal(err)
			}
			if !IsManagedSettingsDropIn(data) {
				t.Error("drop-in not recognised as Kontext's")
			}
			if err := Validate(data, tt.binary); err != nil {
				t.Errorf("Validate() = %v", err)
			}
			if !HasManagedObserveHooks(data) {
				t.Error("HasManagedObserveHooks() = false")
			}
			if got, ok := ManagedObserveHookBinary(data); !ok || got != tt.binary {
				t.Errorf("ManagedObserveHookBinary() = %q, %v", got, ok)
			}
			var partial Settings
			if err := json.Unmarshal(data, &partial); err != nil {
				t.Fatal(err)
			}
			delete(partial.Hooks, "Stop")
			partialData, _ := json.Marshal(partial)
			if missing, binary := MissingRequiredEvents(partialData); len(missing) != 1 || binary != tt.binary {
				t.Errorf("MissingRequiredEvents() = %v, %q", missing, binary)
			}

			settings := decode(t, `{"env":{"KEEP":"1"},"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo mine"}]}]}}`)
			if _, err := MergeManagedHooks(settings, tt.binary); err != nil {
				t.Fatal(err)
			}
			first, _ := json.Marshal(settings)
			if !UserHooksMatch(first, tt.binary) {
				t.Errorf("UserHooksMatch() = false after merge:\n%s", first)
			}
			if got := KontextBinaries(first); !reflect.DeepEqual(got, []string{tt.binary}) {
				t.Errorf("KontextBinaries() = %v", got)
			}
			if _, err := MergeManagedHooks(settings, tt.binary); err != nil {
				t.Fatal(err)
			}
			if second, _ := json.Marshal(settings); string(second) != string(first) {
				t.Errorf("second merge changed settings:\n%s\n%s", first, second)
			}
			if err := RemoveManagedHooks(settings); err != nil {
				t.Fatal(err)
			}
			if got, _ := json.Marshal(settings); string(got) != `{"env":{"KEEP":"1"},"hooks":{"PreToolUse":[{"hooks":[{"command":"echo mine","type":"command"}],"matcher":"Bash"}]}}` {
				t.Errorf("remove left %s", got)
			}
		})
	}
}

// An install in exec form replaces Kontext's earlier entries, whatever form
// and letter case they have, instead of adding a second handler.
func TestExecFormMergeReplacesOlderEntries(t *testing.T) {
	useForm(t, true)
	binary := `C:\Program Files\Kontext\kontext.exe`
	for name, old := range map[string]string{
		"shell form":          `{"type":"command","command":"'C:\\Program Files\\Kontext\\kontext.exe' hook 'pre-tool-use'","timeout":20}`,
		"exec form, old path": `{"type":"command","command":"C:\\Users\\t\\Downloads\\KONTEXT.EXE","args":["hook","pre-tool-use"]}`,
		"POSIX shell form":    `{"type":"command","command":"'/usr/local/bin/kontext' hook 'pre-tool-use'","timeout":20}`,
	} {
		t.Run(name, func(t *testing.T) {
			settings := decode(t, `{"hooks":{"PreToolUse":[{"matcher":"","hooks":[`+old+`]}]}}`)
			if _, err := MergeManagedHooks(settings, binary); err != nil {
				t.Fatal(err)
			}
			groups := eventGroups(t, settings, "PreToolUse")
			if len(groups) != 1 {
				t.Fatalf("PreToolUse groups = %d, want the old entry replaced: %v", len(groups), groups)
			}
			handler := groups[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
			if handler["command"] != binary || !reflect.DeepEqual(handler["args"], []any{"hook", "pre-tool-use"}) {
				t.Fatalf("handler = %v, want exec form", handler)
			}
		})
	}
}

// Under exec form a shell-form hook doesn't count as installed: on Windows it
// runs in PowerShell, which can't parse it.
func TestValidateExecFormRejectsShellForm(t *testing.T) {
	binary := `C:\Program Files\Kontext\kontext.exe`
	shell, err := TemplateJSON(binary) // TestMain pins the shell form
	if err != nil {
		t.Fatal(err)
	}
	useForm(t, true)
	if err := Validate(shell, binary); err == nil || !strings.Contains(err.Error(), "must name the binary in command") {
		t.Fatalf("Validate(shell form) = %v, want the exec-form error", err)
	}
	if UserHooksMatch(shell, binary) {
		t.Fatal("UserHooksMatch(shell form) = true under exec form")
	}
}

// Ownership: which handlers are Kontext's own flagless hooks, in either form.
func TestManagedHookHandlerForms(t *testing.T) {
	for _, tt := range []struct {
		name    string
		handler agenthooks.CommandHandler
		want    bool
	}{
		{"shell form", agenthooks.CommandHandler{Command: "'/usr/local/bin/kontext' hook 'pre-tool-use'"}, true},
		{"shell form, Windows path", agenthooks.CommandHandler{Command: `'C:\Program Files\Kontext\kontext.exe' hook 'pre-tool-use'`}, true},
		{"exec form", agenthooks.CommandHandler{Command: `C:\Program Files\Kontext\kontext.exe`, Args: []string{"hook", "pre-tool-use"}}, true},
		{"exec form without spaces", agenthooks.CommandHandler{Command: `C:\Users\t\kontext.exe`, Args: []string{"hook", "stop"}}, true},
		{"exec form, upper case", agenthooks.CommandHandler{Command: `C:\Users\t\KONTEXT.EXE`, Args: []string{"hook", "stop"}}, true},
		{"exec form, quoted path", agenthooks.CommandHandler{Command: `'/Applications/Kontext CLI/kontext'`, Args: []string{"hook", "stop"}}, true},
		{"mixed form", agenthooks.CommandHandler{Command: `'C:\Users\t\kontext.exe' hook 'stop'`, Args: []string{"hook", "stop"}}, false},
		{"guard flags", agenthooks.CommandHandler{Command: `C:\Users\t\kontext.exe`, Args: []string{"hook", "--agent", "claude", "--mode", "observe"}}, false},
		{"other binary", agenthooks.CommandHandler{Command: `C:\Users\t\kontext.cmd`, Args: []string{"hook", "stop"}}, false},
		{"unknown alias", agenthooks.CommandHandler{Command: `C:\Users\t\kontext.exe`, Args: []string{"hook", "nope"}}, false},
	} {
		if got := isManagedHookHandler(tt.handler); got != tt.want {
			t.Errorf("%s: isManagedHookHandler() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestGuardHookHandlerAcceptsKontextExe(t *testing.T) {
	handler := agenthooks.CommandHandler{Command: `C:\Users\t\Kontext.exe`, Args: []string{"hook", "--agent", "claude", "--mode", "observe"}}
	if !isGuardHookHandler(handler) {
		t.Fatal("Guard's exec-form hook with kontext.exe not recognised")
	}
}

func compact(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	// Compact keeps the field order Claude Code reads.
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		t.Fatal(err)
	}
	return out.String()
}
