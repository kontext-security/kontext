package codexmanaged

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
)

// formOnThisOS is the form the package writes by default on the OS the tests
// run on, read before TestMain pins the POSIX form.
var formOnThisOS = PowerShellForm

// The package's other tests are about the POSIX form, with POSIX paths, on
// every OS; the tests here turn the PowerShell form on for themselves.
func TestMain(m *testing.M) {
	PowerShellForm = false
	os.Exit(m.Run())
}

// Windows is where Codex hands hook commands to PowerShell, and only there.
func TestPowerShellFormIsTheDefaultOnWindowsOnly(t *testing.T) {
	if want := runtime.GOOS == "windows"; formOnThisOS != want {
		t.Fatalf("PowerShellForm defaults to %v on %s, want %v", formOnThisOS, runtime.GOOS, want)
	}
}

// writeFor makes the package write hooks for os until the test ends.
func writeFor(t *testing.T, goos string) {
	t.Helper()
	previous := PowerShellForm
	PowerShellForm = goos == "windows"
	t.Cleanup(func() { PowerShellForm = previous })
}

// On Windows every Codex hook is written for PowerShell, which Codex hands
// the command to, and the written file passes the package's own checks.
func TestTemplateOnWindowsIsWrittenForPowerShell(t *testing.T) {
	writeFor(t, "windows")
	const binary = `C:\Program Files\Kontext\kontext.exe`

	data, err := TemplateJSON(binary)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range SupportedEvents {
		want := `$LASTEXITCODE = 1; & 'C:\Program Files\Kontext\kontext.exe' 'hook' '--agent' 'codex' '` + event.Alias + `'; exit $LASTEXITCODE`
		handlers := Template(binary).Hooks[event.Name.String()]
		if len(handlers) != 1 || len(handlers[0].Hooks) != 1 || handlers[0].Hooks[0].Command != want {
			t.Fatalf("%s hook = %+v, want the command %s", event.Name, handlers, want)
		}
	}
	if err := Validate(data, binary); err != nil {
		t.Fatalf("Validate() of the Windows template = %v", err)
	}
	got, err := ValidateInstalled(data)
	if err != nil || got != binary {
		t.Fatalf("ValidateInstalled() = %q, %v, want %s", got, err, binary)
	}
	if covered := Coverage(data); len(covered) != len(SupportedEvents) {
		t.Fatalf("Coverage() = %v, want every event", covered)
	}
}

// Kontext's hooks are found again in both forms, so a file written on one OS
// form is recognised whatever OS reads it, and removed without a trace.
func TestManagedHookCommandIsRecognisedInBothForms(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		want    bool
	}{
		{name: "PowerShell form", command: `$LASTEXITCODE = 1; & 'C:\Users\someone\kontext.exe' 'hook' '--agent' 'codex' 'pre-tool-use'; exit $LASTEXITCODE`, want: true},
		{name: "PowerShell form, another spelling of the name", command: `$LASTEXITCODE = 1; & 'C:/tools/KONTEXT.EXE' 'hook' '--agent' 'codex' 'stop'; exit $LASTEXITCODE`, want: true},
		{name: "POSIX form", command: `'/usr/local/bin/kontext' 'hook' '--agent' 'codex' 'pre-tool-use'`, want: true},
		{name: "PowerShell form of another program", command: `$LASTEXITCODE = 1; & 'C:\tools\notkontext.exe' 'hook' '--agent' 'codex' 'pre-tool-use'; exit $LASTEXITCODE`},
		{name: "PowerShell form without the .exe", command: `$LASTEXITCODE = 1; & 'C:\tools\kontext' 'hook' '--agent' 'codex' 'pre-tool-use'; exit $LASTEXITCODE`},
		{name: "PowerShell form of another agent", command: `$LASTEXITCODE = 1; & 'C:\tools\kontext.exe' 'hook' '--agent' 'cursor' 'pre-tool-use'; exit $LASTEXITCODE`},
		{name: "PowerShell form with an unknown event", command: `$LASTEXITCODE = 1; & 'C:\tools\kontext.exe' 'hook' '--agent' 'codex' 'something'; exit $LASTEXITCODE`},
		{name: "PowerShell form with one more command", command: `$LASTEXITCODE = 1; & 'C:\tools\kontext.exe' 'hook' '--agent' 'codex' 'stop'; calc; exit $LASTEXITCODE`},
		{name: "POSIX form of kontext.exe", command: `'C:/tools/kontext.exe' 'hook' '--agent' 'codex' 'stop'`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsManagedHookCommand(tc.command); got != tc.want {
				t.Fatalf("IsManagedHookCommand(%s) = %v, want %v", tc.command, got, tc.want)
			}
		})
	}
}

// Merging and removing work on a Windows file, beside a hook of the user's.
func TestMergeAndRemoveOnWindowsKeepTheUsersHooks(t *testing.T) {
	writeFor(t, "windows")
	settings := map[string]any{}
	if err := json.Unmarshal([]byte(`{"hooks":{"PreToolUse":[{"matcher":"","hooks":[{"type":"command","command":"& 'C:\\mine\\audit.exe'","timeout":5}]}]}}`), &settings); err != nil {
		t.Fatal(err)
	}
	const binary = `C:\Users\someone\AppData\Local\kontext.exe`
	if err := MergeManagedHooks(settings, binary); err != nil {
		t.Fatalf("MergeManagedHooks() = %v", err)
	}
	merged, _ := json.Marshal(settings)
	if err := Validate(merged, binary); err != nil {
		t.Fatalf("Validate() after the merge = %v\n%s", err, merged)
	}
	if !strings.Contains(string(merged), "audit.exe") {
		t.Fatalf("the merge dropped the user's hook:\n%s", merged)
	}
	// Merging again with a moved program replaces Kontext's entries.
	const moved = `D:\elsewhere\kontext.exe`
	if err := MergeManagedHooks(settings, moved); err != nil {
		t.Fatal(err)
	}
	merged, _ = json.Marshal(settings)
	if strings.Contains(string(merged), `AppData`) || Validate(merged, moved) != nil {
		t.Fatalf("after a second merge the old program's hooks are still there, or the new ones are not valid:\n%s", merged)
	}

	if err := RemoveManagedHooks(settings); err != nil {
		t.Fatalf("RemoveManagedHooks() = %v", err)
	}
	left, _ := json.Marshal(settings)
	if strings.Contains(string(left), "kontext.exe") || !strings.Contains(string(left), "audit.exe") {
		t.Fatalf("after the removal:\n%s", left)
	}
}
