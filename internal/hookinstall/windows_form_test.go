package hookinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/codexmanaged"
)

// asWindows installs as on Windows: Claude Code's exec form, Codex's hooks
// for PowerShell, kontext.exe, and no Cursor file. It returns a temporary home and a kontext.exe in
// it; the machine-wide files a user install reads are moved there too.
func asWindows(t *testing.T) (home, binary string) {
	t.Helper()
	t.Setenv("CODEX_HOME", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	goos, exec, powerShell := runtimeGOOS, claudemanaged.ExecForm, codexmanaged.PowerShellForm
	runtimeGOOS, claudemanaged.ExecForm, codexmanaged.PowerShellForm = "windows", true, true
	claudeDropIn, cursorHooks, codexHooks := machineClaudeDropIn, machineCursorHooks, machineCodexHooks
	root := t.TempDir()
	machineClaudeDropIn = filepath.Join(root, "ClaudeCode", "managed-settings.d", "20-kontext.json")
	machineCursorHooks = filepath.Join(root, "Cursor", "hooks.json")
	machineCodexHooks = filepath.Join(root, "Codex", "hooks.json")
	t.Cleanup(func() {
		runtimeGOOS, claudemanaged.ExecForm, codexmanaged.PowerShellForm = goos, exec, powerShell
		machineClaudeDropIn, machineCursorHooks, machineCodexHooks = claudeDropIn, cursorHooks, codexHooks
	})
	home = filepath.Join(root, "home")
	binary = filepath.Join(root, "Kontext", "kontext.exe")
	write(t, binary, "MZ", 0755)
	return home, binary
}

// lines splits the command's output into its tab-separated fields.
func lines(out string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows
}

func TestWindowsUserInstallWritesClaudeExecFormAndCodexForPowerShell(t *testing.T) {
	home, binary := asWindows(t)
	var out bytes.Buffer
	opts := Options{Scope: User, Home: home, Binary: binary, Out: &out}
	if err := Install(opts); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	data := read(t, settings)
	if !claudemanaged.UserHooksMatch([]byte(data), binary) {
		t.Fatalf("settings.json is not the exec-form hook set:\n%s", data)
	}
	var parsed struct {
		Hooks map[string][]struct {
			Hooks []map[string]any `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		t.Fatal(err)
	}
	handler := parsed.Hooks["PreToolUse"][0].Hooks[0]
	if handler["command"] != binary || len(handler["args"].([]any)) != 2 {
		t.Fatalf("PreToolUse handler = %v, want command %q and args", handler, binary)
	}
	// Codex's hooks are written for PowerShell, which Codex hands them to.
	codexHooks := filepath.Join(home, ".codex", "hooks.json")
	if err := codexmanaged.Validate([]byte(read(t, codexHooks)), binary); err != nil {
		t.Fatalf("Codex's hooks.json is not the hook set for %s: %v\n%s", binary, err, read(t, codexHooks))
	}
	var codex struct {
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal([]byte(read(t, codexHooks)), &codex); err != nil {
		t.Fatal(err)
	}
	if got, want := codex.Hooks["PreToolUse"][0].Hooks[0].Command, "$LASTEXITCODE = 1; & '"+binary+"' 'hook' '--agent' 'codex' 'pre-tool-use'; exit $LASTEXITCODE"; got != want {
		t.Fatalf("Codex's PreToolUse command = %s, want %s", got, want)
	}
	// Codex's own config, where it keeps the user's settings and the trust
	// given to hooks, is not written, and Cursor gets nothing.
	for _, path := range []string{filepath.Join(home, ".codex", "config.toml"), filepath.Join(home, ".cursor")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("%s exists after a Windows install (err %v)", path, err)
		}
	}
	// Claude's and Codex's hook files are written; Codex's feature flag is
	// left alone as on by default; every other agent's file is reported as
	// unsupported, however many agents the install knows.
	unsupported := 0
	for _, row := range lines(out.String()) {
		if len(row) != 4 {
			t.Fatalf("output row %q has %d fields, want 4", strings.Join(row, "\t"), len(row))
		}
		switch {
		case strings.HasPrefix(row[2], filepath.Join(home, ".claude")), row[2] == codexHooks:
			if row[0] != "write" {
				t.Errorf("want this file written: %v", row)
			}
		case row[2] == filepath.Join(home, ".codex", "config.toml"):
			if row[0] != "skip" || row[3] != windowsHooksOnByDefault {
				t.Errorf("want Codex's feature flag left alone as on by default: %v", row)
			}
		default:
			if row[0] != "skip" || row[3] != windowsUnsupported {
				t.Errorf("want this file reported as unsupported: %v", row)
			}
			unsupported++
		}
	}
	if unsupported < 1 {
		t.Fatalf("want at least Cursor's file reported as unsupported, got:\n%s", out.String())
	}

	// A rerun changes nothing, and remove takes out every entry install wrote.
	out.Reset()
	if err := Install(opts); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "skip\tuser\t"+settings+"\tunchanged\n") {
		t.Fatalf("rerun output:\n%s", out.String())
	}
	if err := Remove(opts); err != nil {
		t.Fatal(err)
	}
	if got := read(t, settings); strings.Contains(strings.ToLower(got), "kontext") {
		t.Fatalf("remove left Kontext entries:\n%s", got)
	}
	if got, err := os.ReadFile(codexHooks); err == nil && strings.Contains(strings.ToLower(string(got)), "kontext") {
		t.Fatalf("remove left Kontext entries in Codex's hooks.json:\n%s", got)
	}
}

// A machine drop-in an older version wrote in the shell form doesn't run under
// PowerShell, so a user install must write its own exec form, not copy it.
func TestWindowsUserInstallDoesNotCopyAShellFormMachineHook(t *testing.T) {
	home, binary := asWindows(t)
	claudemanaged.ExecForm = false
	shell, err := json.Marshal(claudemanaged.Template(binary))
	claudemanaged.ExecForm = true
	if err != nil {
		t.Fatal(err)
	}
	write(t, machineClaudeDropIn, string(shell), 0644)

	var out bytes.Buffer
	if err := Install(Options{Scope: User, Home: home, Binary: binary, Out: &out}); err != nil {
		t.Fatal(err)
	}
	data := read(t, filepath.Join(home, ".claude", "settings.json"))
	if !claudemanaged.UserHooksMatch([]byte(data), binary) {
		t.Fatalf("settings.json is not the exec-form hook set:\n%s", data)
	}
	if strings.Contains(data, " hook ") {
		t.Fatalf("a shell-form hook was copied:\n%s", data)
	}
}

// The shell-form drop-in may name an older kontext.exe that still exists; the
// user copy takes the binary it was given, not that one.
func TestWindowsUserInstallIgnoresAShellFormMachineHooksBinary(t *testing.T) {
	home, binary := asWindows(t)
	old := filepath.Join(filepath.Dir(binary), "old", "kontext.exe")
	write(t, old, "MZ", 0755)
	claudemanaged.ExecForm = false
	shell, err := json.Marshal(claudemanaged.Template(old))
	claudemanaged.ExecForm = true
	if err != nil {
		t.Fatal(err)
	}
	write(t, machineClaudeDropIn, string(shell), 0644)

	if err := Install(Options{Scope: User, Home: home, Binary: binary, Out: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	data := read(t, filepath.Join(home, ".claude", "settings.json"))
	if !claudemanaged.UserHooksMatch([]byte(data), binary) || strings.Contains(data, old) {
		t.Fatalf("settings.json doesn't name %s alone:\n%s", binary, data)
	}
}

func TestWindowsSystemInstallWritesTheManagedDropIn(t *testing.T) {
	_, binary := asWindows(t)
	dropIn := filepath.Join(t.TempDir(), "ClaudeCode", "managed-settings.d", "20-kontext.json")
	cursor := filepath.Join(t.TempDir(), "Cursor", "hooks.json")
	var out bytes.Buffer
	opts := Options{Scope: System, Home: "", Binary: binary, Out: &out, ClaudePath: dropIn, CursorPath: cursor}
	if err := Install(opts); err != nil {
		t.Fatal(err)
	}
	data := []byte(read(t, dropIn))
	want, err := claudemanaged.TemplateJSON(binary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) || !bytes.Contains(data, []byte(`"args"`)) {
		t.Fatalf("drop-in is not the exec-form template:\n%s", data)
	}
	if _, err := os.Lstat(filepath.Dir(cursor)); !os.IsNotExist(err) {
		t.Errorf("Cursor's folder was created (err %v)", err)
	}
	out.Reset()
	if err := Install(opts); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "skip\tsystem\t"+dropIn+"\tunchanged\n") {
		t.Fatalf("rerun output:\n%s", out.String())
	}
	if err := Remove(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dropIn); !os.IsNotExist(err) {
		t.Fatalf("remove kept the drop-in (err %v)", err)
	}
}

func TestWindowsInstallWantsKontextExe(t *testing.T) {
	home, binary := asWindows(t)
	for name, path := range map[string]string{
		"no extension": filepath.Join(filepath.Dir(binary), "kontext"),
		"other name":   filepath.Join(filepath.Dir(binary), "kontext-dev.exe"),
	} {
		t.Run(name, func(t *testing.T) {
			write(t, path, "MZ", 0755)
			err := Install(Options{Scope: User, Home: home, Binary: path, DryRun: true})
			if err == nil || !strings.Contains(err.Error(), "kontext.exe") {
				t.Fatalf("Install(%s) = %v, want a kontext.exe error", filepath.Base(path), err)
			}
		})
	}
	upper := filepath.Join(filepath.Dir(binary), "KONTEXT.EXE")
	if err := Install(Options{Scope: User, Home: home, Binary: upper, DryRun: true}); err != nil {
		t.Fatalf("Install(KONTEXT.EXE) = %v", err)
	}
}

func TestWindowsDoctorDoesNotExpectSkippedAgents(t *testing.T) {
	home, binary := asWindows(t)
	if err := Install(Options{Scope: User, Home: home, Binary: binary, Out: &bytes.Buffer{}}); err != nil {
		t.Fatal(err)
	}
	defs, err := Definitions(User, home)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	everyAgent := func(string) bool { return true }
	if !diagnose(&out, User, defs, everyAgent, filepath.Join(home, ".codex", "config.toml"), machineCodexHooks) {
		t.Fatalf("doctor reports a Windows install as unhealthy:\n%s", out.String())
	}
	if want := "Cursor hooks: not installed (" + windowsUnsupported + ")"; strings.Count(out.String(), want) != 1 {
		t.Errorf("want %q once, got:\n%s", want, out.String())
	}
	// Codex's hooks are installed, and doctor says what is still to do: Codex
	// runs them only once the user trusts them.
	for _, want := range []string{"Codex hooks: installed (" + filepath.Join(home, ".codex", "hooks.json"), "Codex hooks: not trusted in Codex ("} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("want %q, got:\n%s", want, out.String())
		}
	}
}
