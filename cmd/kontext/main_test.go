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

	"github.com/kontext-security/kontext-cli/internal/agent"
	"github.com/kontext-security/kontext-cli/internal/claudemanaged"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestRootCmdExposesSupportedCommandsOnly(t *testing.T) {
	root := newRootCmd()
	for _, name := range []string{"setup", "hook", "managed-observe-daemon", "doctor", "claude", "guard"} {
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
	stubEnv(t, nil)
	a, ok := agent.Get("claude")
	if !ok {
		t.Fatal("claude agent not registered")
	}
	tests := []struct{ name, input, want string }{
		{"cowork cwd", `{"session_id":"s1","hook_event_name":"PreToolUse","cwd":"/Users/michel/Library/Application Support/Claude/local-agent-mode-sessions/acme/ws/local_123/repo"}`, "cowork"},
		{"cowork transcript", `{"session_id":"s1","hook_event_name":"PreToolUse","transcript_path":"/Users/michel/Library/Application Support/Claude/local-agent-mode-sessions/acme/ws/local_123/transcript.jsonl"}`, "cowork"},
		{"ordinary claude", `{"session_id":"s1","hook_event_name":"PreToolUse","cwd":"/Users/michel/project"}`, "claude"},
		{"lookalike path", `{"session_id":"s1","hook_event_name":"PreToolUse","cwd":"/Users/michel/work/Library/Application Support/Claude/local-agent-mode-sessions/acme/ws/local_123/repo"}`, "claude"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event, err := (managedHookAgent{Agent: a}).DecodeHookInput([]byte(tt.input))
			if err != nil {
				t.Fatalf("DecodeHookInput() error = %v", err)
			}
			if event.Agent != tt.want {
				t.Fatalf("Agent = %q, want %q", event.Agent, tt.want)
			}
		})
	}
}

// stubEnv replaces the process environment lookup for the duration of a test.
func stubEnv(t *testing.T, env map[string]string) {
	t.Helper()
	old := lookupEnv
	lookupEnv = func(key string) string { return env[key] }
	t.Cleanup(func() { lookupEnv = old })
}

// Cowork opened on a folder or repository runs on the host with the working
// directory set to the user's own checkout and a transcript under ~/.claude, so
// no path in the hook payload identifies it. Before the host-session check these
// sessions were recorded as plain Claude Code and never appeared under Cowork.
func TestManagedHookAgentIdentifiesCoworkRunningOnHost(t *testing.T) {
	oldHome := userHomeDir
	userHomeDir = func() (string, error) { return "/Users/michel", nil }
	t.Cleanup(func() { userHomeDir = oldHome })
	a, ok := agent.Get("claude")
	if !ok {
		t.Fatal("claude agent not registered")
	}
	const hostSession = `{"session_id":"s1","hook_event_name":"PreToolUse",` +
		`"cwd":"/Users/michel/projects/app/.claude/worktrees/feature-abc123",` +
		`"transcript_path":"/Users/michel/.claude/projects/-Users-michel-projects-app/s1.jsonl"}`
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"cowork host session", map[string]string{"CLAUDE_CODE_HOST_SESSION_ID": "local_9826bfca-2687"}, "cowork"},
		{"no host session id", nil, "claude"},
		{"empty host session id", map[string]string{"CLAUDE_CODE_HOST_SESSION_ID": ""}, "claude"},
		{"non-cowork host session id", map[string]string{"CLAUDE_CODE_HOST_SESSION_ID": "remote_9826bfca"}, "claude"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubEnv(t, tt.env)
			event, err := (managedHookAgent{Agent: a}).DecodeHookInput([]byte(hostSession))
			if err != nil {
				t.Fatalf("DecodeHookInput() error = %v", err)
			}
			if event.Agent != tt.want {
				t.Fatalf("Agent = %q, want %q", event.Agent, tt.want)
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
