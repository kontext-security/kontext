package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGuardHookCompatibilityCommandIsRetired(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(context.Background(), []string{"hook", "claude-code"}, strings.NewReader(`{}`), &stdout, &stderr)
	if err == nil {
		t.Fatal("Run() error = nil, want retired command error")
	}
	if !strings.Contains(err.Error(), `unknown command "hook"`) {
		t.Fatalf("error = %v, want unknown hook command", err)
	}
}

func TestInstalledHookCommandUsesStableLauncherOverride(t *testing.T) {
	t.Setenv("KONTEXT_GUARD_HOOK_COMMAND", "'/usr/local/bin/kontext' hook --agent claude --mode observe")

	got := installedHookCommand("/tmp/kontext-custom.sock")
	if strings.Contains(got, "go-build") {
		t.Fatalf("hook command should not use transient Go build cache path: %s", got)
	}
	if !strings.Contains(got, "hook --agent claude --mode observe") {
		t.Fatalf("hook command did not use launcher override: %s", got)
	}
}

func TestInstalledHookCommandUsesCanonicalRootHookHandler(t *testing.T) {
	t.Setenv("KONTEXT_GUARD_HOOK_COMMAND", "")

	got := installedHookCommand("/tmp/kontext-custom.sock")
	if strings.Contains(got, "guard hook claude-code") {
		t.Fatalf("hook command used legacy Guard handler: %s", got)
	}
	if !strings.Contains(got, "hook --agent claude") {
		t.Fatalf("hook command did not use canonical root handler: %s", got)
	}
	if !strings.Contains(got, `--mode observe`) {
		t.Fatalf("hook command did not pin local hooks to observe mode: %s", got)
	}
	if !strings.Contains(got, "--socket ") || !strings.Contains(got, "/tmp/kontext-custom.sock") {
		t.Fatalf("hook command did not carry custom socket path: %s", got)
	}
}

func TestIsGuardHookCommandRecognizesInstalledGuardHooks(t *testing.T) {
	t.Parallel()

	for _, command := range []string{
		"/usr/local/bin/kontext guard hook claude-code",
		"'/usr/local/bin/kontext' guard hook claude-code",
		"/usr/local/bin/kontext hook --agent claude --mode observe",
		"'/usr/local/bin/kontext' hook --agent claude --mode observe",
		"cd '/repo' && go run ./cmd/kontext hook --agent claude --mode observe",
		`/usr/local/bin/kontext hook --agent claude --mode observe --socket /tmp/kontext-custom.sock`,
	} {
		if !isGuardHookCommand(command) {
			t.Fatalf("isGuardHookCommand(%q) = false, want true", command)
		}
	}
	if isGuardHookCommand("/usr/local/bin/kontext hook --agent claude") {
		t.Fatal("hosted/pass-through hook should not be classified as Guard observe hook")
	}
}

func TestMergeHooksInstallsOnlyToolHooks(t *testing.T) {
	t.Parallel()

	hooks := mergeHooks(map[string]any{
		"UserPromptSubmit": []any{
			map[string]any{
				"hooks": []any{
					map[string]any{
						"type":    "command",
						"command": "/usr/local/bin/kontext guard hook claude-code",
					},
				},
			},
		},
	}, `/usr/local/bin/kontext hook --agent claude --mode observe --socket /tmp/kontext.sock`)

	if _, ok := hooks["PreToolUse"]; !ok {
		t.Fatal("PreToolUse hook missing")
	}
	if _, ok := hooks["PostToolUse"]; !ok {
		t.Fatal("PostToolUse hook missing")
	}
	if _, ok := hooks["UserPromptSubmit"]; ok {
		t.Fatal("UserPromptSubmit hook installed, want only tool hooks")
	}
}

func TestMergeHooksPreservesNonGuardHookInMixedGroup(t *testing.T) {
	t.Parallel()

	hooks := mergeHooks(map[string]any{
		"PreToolUse": []any{
			map[string]any{
				"matcher": "Bash",
				"hooks": []any{
					map[string]any{
						"type":    "command",
						"command": "/usr/local/bin/custom-hook",
					},
					map[string]any{
						"type":    "command",
						"command": "/usr/local/bin/kontext hook --agent claude --mode observe",
					},
				},
			},
		},
	}, `/usr/local/bin/kontext hook --agent claude --mode observe --socket /tmp/kontext.sock`)

	list := hooks["PreToolUse"].([]any)
	group := list[0].(map[string]any)
	if group["matcher"] != "Bash" {
		t.Fatalf("matcher = %v, want Bash", group["matcher"])
	}
	groupHooks := group["hooks"].([]any)
	if len(groupHooks) != 1 {
		t.Fatalf("mixed group hook count = %d, want 1", len(groupHooks))
	}
	command := groupHooks[0].(map[string]any)["command"]
	if command != "/usr/local/bin/custom-hook" {
		t.Fatalf("preserved command = %v, want custom hook", command)
	}
}

func TestUninstallClaudeHooksPreservesNonGuardHookInMixedGroup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/custom-hook"},
          {"type": "command", "command": "/usr/local/bin/kontext hook --agent claude --mode observe"}
        ]
      }
    ]
  }
}`
	if err := os.WriteFile(settingsPath, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	if err := uninstallClaudeHooks(&stdout); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}

	hooks := got["hooks"].(map[string]any)
	list := hooks["PreToolUse"].([]any)
	group := list[0].(map[string]any)
	if group["matcher"] != "Bash" {
		t.Fatalf("matcher = %v, want Bash", group["matcher"])
	}
	groupHooks := group["hooks"].([]any)
	if len(groupHooks) != 1 {
		t.Fatalf("mixed group hook count = %d, want 1", len(groupHooks))
	}
	command := groupHooks[0].(map[string]any)["command"]
	if command != "/usr/local/bin/custom-hook" {
		t.Fatalf("preserved command = %v, want custom hook", command)
	}
}

func TestPrintHookStatusReportsGuardAndHostedConflict(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	settingsPath := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	settings := `{
  "hooks": {
    "PreToolUse": [
      {
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/kontext hook --agent claude --mode observe"}
        ]
      }
    ],
    "PostToolUse": [
      {
        "hooks": [
          {"type": "command", "command": "'/usr/local/bin/kontext' hook 'post-tool-use'"},
          {"type": "command", "command": "/usr/local/bin/not-kontext hook post-tool-use"}
        ]
      }
    ]
  }
}`
	if err := os.WriteFile(settingsPath, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	PrintHookStatus(&out)

	got := out.String()
	if !strings.Contains(got, "Claude Code Guard hook: /usr/local/bin/kontext hook --agent claude --mode observe") {
		t.Fatalf("PrintHookStatus() = %q, want guard hook line", got)
	}
	if !strings.Contains(got, "Claude Code hosted hook: '/usr/local/bin/kontext' hook 'post-tool-use'") {
		t.Fatalf("PrintHookStatus() = %q, want hosted hook line", got)
	}
	if strings.Contains(got, "not-kontext") {
		t.Fatalf("PrintHookStatus() = %q, want foreign hook ignored", got)
	}
	if !strings.Contains(got, "Claude Code local Guard hook mode: conflict (hosted and Guard hooks are both installed)") {
		t.Fatalf("PrintHookStatus() = %q, want conflict mode", got)
	}
}
