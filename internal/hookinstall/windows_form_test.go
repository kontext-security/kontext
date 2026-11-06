package hookinstall

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/claudemanaged"
)

// asWindows installs as on Windows: Claude Code's exec form, kontext.exe, and
// no Codex or Cursor files. It returns a temporary home and a kontext.exe in
// it; the machine-wide files a user install reads are moved there too.
func asWindows(t *testing.T) (home, binary string) {
	t.Helper()
	t.Setenv("CODEX_HOME", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	goos, exec := runtimeGOOS, claudemanaged.ExecForm
	runtimeGOOS, claudemanaged.ExecForm = "windows", true
	claudeDropIn, cursorHooks, codexHooks := machineClaudeDropIn, machineCursorHooks, machineCodexHooks
	root := t.TempDir()
	machineClaudeDropIn = filepath.Join(root, "ClaudeCode", "managed-settings.d", "20-kontext.json")
	machineCursorHooks = filepath.Join(root, "Cursor", "hooks.json")
	machineCodexHooks = filepath.Join(root, "Codex", "hooks.json")
	t.Cleanup(func() {
		runtimeGOOS, claudemanaged.ExecForm = goos, exec
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

func TestWindowsUserInstallWritesClaudeExecFormOnly(t *testing.T) {
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
	for _, path := range []string{filepath.Join(home, ".codex"), filepath.Join(home, ".cursor")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("%s exists after a Windows install (err %v)", path, err)
		}
	}
	skipped := 0
	for _, row := range lines(out.String()) {
		if len(row) == 4 && row[0] == "skip" && row[3] == windowsUnsupported {
			skipped++
		}
	}
	if skipped != 3 {
		t.Fatalf("want Codex's two files and Cursor's reported as unsupported, got:\n%s", out.String())
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
