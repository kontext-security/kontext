package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/agent"
	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/hook"
)

func TestRootCmdExposesSupportedCommandsOnly(t *testing.T) {
	root := newRootCmd()
	for _, name := range []string{"setup", "hook", "managed-observe-daemon", "doctor", "risk-types", "claude", "guard"} {
		if _, _, err := root.Find([]string{name}); err != nil {
			t.Fatalf("root command missing %q: %v", name, err)
		}
	}
	for _, name := range []string{"start", "login", "logout"} {
		if _, _, err := root.Find([]string{name}); err == nil {
			t.Fatalf("root command still exposes retired %q command", name)
		}
	}
}

func TestGuardCmdRoutesToLocalGuardMode(t *testing.T) {
	cmd := guardCmd()
	if cmd.Use != "guard" || !cmd.DisableFlagParsing {
		t.Fatalf("guard command = %+v, want local flag passthrough", cmd)
	}
}

func TestHookCmdModeDoesNotDefaultFromEnv(t *testing.T) {
	t.Setenv("KONTEXT_MODE", "observe")
	flag := hookCmd().Flags().Lookup("mode")
	if flag == nil || flag.DefValue != "" {
		t.Fatalf("--mode = %v, want empty default", flag)
	}
}

func TestManagedObserveSelection(t *testing.T) {
	writeManagedConfigForCmdTest(t)
	tests := []struct {
		name, socket                       string
		explicitSocket, explicitMode, want bool
	}{
		{"managed config", "", false, false, true},
		{"environment socket", filepath.Join(t.TempDir(), "kontext.sock"), false, false, false},
		{"explicit socket", "", true, false, false},
		{"explicit mode", "", false, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("KONTEXT_SOCKET", tt.socket)
			if got := shouldUseManagedObserve(tt.explicitSocket, tt.explicitMode); got != tt.want {
				t.Fatalf("shouldUseManagedObserve() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClaudeManagedSettingsCommands(t *testing.T) {
	data, err := claudemanaged.TemplateJSON("/opt/kontext/bin/kontext")
	if err != nil {
		t.Fatalf("TemplateJSON() error = %v", err)
	}
	cmd := claudeManagedSettingsTemplateCmd()
	cmd.SetArgs([]string{"--kontext-binary", "/opt/kontext/bin/kontext"})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("template Execute() error = %v", err)
	}
	if !bytes.Equal(stdout.Bytes(), data) {
		t.Fatal("template command output differs from generated settings")
	}

	path := filepath.Join(t.TempDir(), "managed-settings.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write settings: %v", err)
	}
	validate := claudeManagedSettingsValidateCmd()
	validate.SetArgs([]string{path, "--kontext-binary", "/opt/kontext/bin/kontext"})
	if err := validate.Execute(); err != nil {
		t.Fatalf("validate Execute() error = %v", err)
	}
}

func TestExpectedHookEventFromArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    hook.HookName
		wantErr bool
	}{
		{"empty", nil, "", false},
		{"pre tool use", []string{"pre-tool-use"}, hook.HookPreToolUse, false},
		{"user prompt", []string{"user-prompt-submit"}, hook.HookUserPromptSubmit, false},
		{"unknown", []string{"pretooluse"}, "", true},
		{"too many", []string{"pre-tool-use", "post-tool-use"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := expectedHookEventFromArgs(tt.args)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Fatalf("got (%q, %v), want (%q, error=%v)", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestManagedHookAgentIdentifiesCoworkOnlyInManagedSessionPath(t *testing.T) {
	oldHome := userHomeDir
	userHomeDir = func() (string, error) { return "/Users/michel", nil }
	t.Cleanup(func() { userHomeDir = oldHome })
	a, ok := agent.Get("claude")
	if !ok {
		t.Fatal("claude agent not registered")
	}
	const root = "/Users/michel/Library/Application Support/Claude/local-agent-mode-sessions"
	tests := []struct{ name, path, want string }{
		{"full session directory", root + "/acme/ws/local_123/outputs", "cowork"},
		{"short session directory", root + "/acme/ws/abc123ef/outputs", "cowork"},
		{"short account and workspace directories", root + "/1234abcd/5678efab/abc123ef/.claude/transcript.jsonl", "cowork"},
		{"short session root", root + "/acme/ws/abc123ef", "cowork"},
		{"ordinary claude", "/Users/michel/project", "claude"},
		{"lookalike path", "/Users/michel/work/Library/Application Support/Claude/local-agent-mode-sessions/acme/ws/abc123ef/outputs", "claude"},
		{"lookalike root", root + "-other/acme/ws/abc123ef/outputs", "claude"},
		{"account directory", root + "/abc123ef", "claude"},
		{"workspace directory", root + "/acme/abc123ef", "claude"},
		{"non-session directory", root + "/acme/ws/rpm/plugin", "claude"},
		{"short name too short", root + "/acme/ws/abc123e/outputs", "claude"},
		{"short name too long", root + "/acme/ws/abc123ef0/outputs", "claude"},
		{"short name not hex", root + "/acme/ws/abc123eg/outputs", "claude"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, field := range []string{"cwd", "transcript_path", "transcriptPath", "session_path", "sessionPath"} {
				t.Run(field, func(t *testing.T) {
					input, err := json.Marshal(map[string]string{
						"session_id":      "s1",
						"hook_event_name": "PreToolUse",
						field:             tt.path,
					})
					if err != nil {
						t.Fatal(err)
					}
					event, err := (managedHookAgent{Agent: a}).DecodeHookInput(input)
					if err != nil {
						t.Fatalf("DecodeHookInput() error = %v", err)
					}
					if event.Agent != tt.want {
						t.Fatalf("Agent = %q, want %q", event.Agent, tt.want)
					}
				})
			}
		})
	}
}

func TestEvaluateViaSidecarFailsOpenOnMarshalError(t *testing.T) {
	socket := filepath.Join("/tmp", fmt.Sprintf("kontext-%d.sock", time.Now().UnixNano()))
	t.Cleanup(func() { _ = os.Remove(socket) })
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	result, err := evaluateViaSidecar(socket, hook.Event{Agent: "claude", HookName: hook.HookPreToolUse, ToolInput: map[string]any{"bad": func() {}}})
	if err != nil || !result.Allowed() || result.Reason != "sidecar marshal error" {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

func TestSidecarFailureSafetyByMode(t *testing.T) {
	tests := []struct {
		name, mode string
		event      hook.Event
		want       hook.Decision
	}{
		{"enforce blocks pre tool", "enforce", hook.Event{HookName: hook.HookPreToolUse}, hook.DecisionDeny},
		{"observe allows pre tool", "observe", hook.Event{HookName: hook.HookPreToolUse}, hook.DecisionAllow},
		{"post tool allows", "enforce", hook.Event{HookName: hook.HookPostToolUse}, hook.DecisionAllow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := evaluateHookWithSidecarForMode("", tt.event, tt.mode)
			if err != nil || result.Decision != tt.want || result.Reason != "sidecar socket missing" {
				t.Fatalf("result = %+v, err = %v", result, err)
			}
		})
	}
}

func writeManagedConfigForCmdTest(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed.json")
	data := map[string]any{"version": "managed-install-v1", "cloud_url": "https://app.kontext.dev", "mode": "observe", "agent": "claude", "credentials": map[string]string{"install_token_ref": "env:KONTEXT_INSTALL_TOKEN"}}
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("KONTEXT_MANAGED_CONFIG", path)
}

func Example_newRootCmd() {
	cmd := newRootCmd()
	fmt.Println(cmd.Use)
	// Output: kontext
}
