package hookinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Opt in with KONTEXT_TEST_CLAUDE_BINARY=/absolute/path/to/claude. This exercises
// the native Claude dispatcher with the actual installer output. A temporary
// executable copy redirects only its system managed-settings directory; no host
// settings, account credentials, model APIs or Kontext daemon are used.
func TestClaudeHookLayersDispatch(t *testing.T) {
	binary := os.Getenv("KONTEXT_TEST_CLAUDE_BINARY")
	if binary == "" || runtime.GOOS != "darwin" {
		t.Skip("requires macOS and KONTEXT_TEST_CLAUDE_BINARY (verified with 2.1.304)")
	}
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	original, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	placeholder := []byte("/Library/Application Support/ClaudeCode")
	if bytes.Count(original, placeholder) != 3 {
		t.Fatal("Claude binary layout changed; review the isolated managed-root redirection")
	}
	short, err := os.MkdirTemp("/tmp", "kt-dual-")
	if err != nil {
		t.Fatal(err)
	}
	managed := short + strings.Repeat("-", len(placeholder)-len(short))
	if err := os.Rename(short, managed); err != nil {
		os.RemoveAll(short)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(managed) })
	probe := filepath.Join(t.TempDir(), "claude")
	if err := os.WriteFile(probe, bytes.ReplaceAll(original, placeholder, []byte(managed)), 0755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("/usr/bin/codesign", "--force", "--sign", "-", probe).CombinedOutput(); err != nil {
		t.Fatalf("sign isolated binary: %v: %s", err, out)
	}
	api := httptest.NewServer(http.HandlerFunc(claudeProbeAPI))
	defer api.Close()

	for _, scenario := range []struct {
		name   string
		scope  Scope
		change string
		want   int
	}{
		{"system_only", System, "", 1},
		{"identical_layers", User, "", 1},
		{"migrated_user_layer", User, "migrate", 1},
		{"user_fallback", User, "shadow", 1},
		{"managed_hooks_only", User, "managed-only", 1},
		{"managed_disable_all", User, "disabled", 0},
		{"different_paths_negative_control", User, "path", 2},
		{"repair_different_paths", User, "repair-path", 1},
		{"different_timeouts_negative_control", User, "timeout", 2},
		{"repair_different_timeouts", User, "repair-timeout", 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if err := os.RemoveAll(managed); err != nil {
				t.Fatal(err)
			}
			home := t.TempDir()
			fake := filepath.Join(home, "kontext")
			write(t, fake, "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' \"$*\" >> \"$KONTEXT_PROBE_EVENTS\"\n", 0755)
			defs, err := Definitions(scenario.scope, home)
			if err != nil {
				t.Fatal(err)
			}
			if scenario.change == "migrate" {
				// Start from the previous Homebrew managed-only layout.
				defs[0].Files = defs[0].Files[:1]
			}
			dropin := filepath.Join(managed, "managed-settings.d", "20-kontext.json")
			defs[0].Files[0].Path = dropin
			opts := Options{Scope: scenario.scope, Home: home, Binary: fake}
			if err := runDefinitions(opts, defs[:1], false); err != nil {
				t.Fatal(err)
			}
			user := filepath.Join(home, ".claude", "settings.json")
			// Preserve a personal permission and hook alongside the installed set.
			var settings map[string]any
			if raw, err := os.ReadFile(user); err == nil {
				_ = json.Unmarshal(raw, &settings)
			}
			if settings == nil {
				settings = map[string]any{}
			}
			hooks, _ := settings["hooks"].(map[string]any)
			if hooks == nil {
				hooks = map[string]any{}
				settings["hooks"] = hooks
			}
			groups, _ := hooks["PreToolUse"].([]any)
			hooks["PreToolUse"] = append(groups, map[string]any{"matcher": "Bash", "hooks": []any{map[string]any{"type": "command", "command": "true"}}})
			settings["permissions"] = map[string]any{"allow": []string{"Bash(ls *)"}}
			raw, _ := json.Marshal(settings)
			write(t, user, string(raw), 0600)
			switch scenario.change {
			case "migrate":
				if err := RefreshClaudeUser(dropin, user, fake); err != nil {
					t.Fatal(err)
				}
			case "shadow":
				if err := os.Remove(dropin); err != nil {
					t.Fatal(err)
				}
				write(t, filepath.Join(managed, "managed-settings.json"), `{"cleanupPeriodDays":30}`, 0644)
			case "managed-only":
				write(t, filepath.Join(managed, "managed-settings.json"), `{"allowManagedHooksOnly":true}`, 0644)
			case "disabled":
				write(t, filepath.Join(managed, "managed-settings.json"), `{"disableAllHooks":true}`, 0644)
			case "path", "repair-path":
				alias := filepath.Join(home, "alias", "kontext")
				if err := os.MkdirAll(filepath.Dir(alias), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(fake, alias); err != nil {
					t.Fatal(err)
				}
				write(t, user, strings.ReplaceAll(string(raw), fake, alias), 0600)
			case "timeout", "repair-timeout":
				write(t, user, strings.ReplaceAll(string(raw), `"timeout":20`, `"timeout":21`), 0600)
			}
			if strings.HasPrefix(scenario.change, "repair-") {
				if err := runDefinitions(opts, defs[:1], false); err != nil {
					t.Fatal(err)
				}
			}
			events := filepath.Join(home, "events.txt")
			workspace := filepath.Join(home, "workspace")
			if err := os.Mkdir(workspace, 0700); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, probe, "-p", "Use Bash to list this directory, then acknowledge.", "--model", "claude-sonnet-4-5")
			cmd.Dir = workspace
			cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "TERM=dumb", "HOME=" + home, "TMPDIR=" + home, "CLAUDE_CONFIG_DIR=" + filepath.Dir(user), "ANTHROPIC_API_KEY=sk-ant-local-probe-not-real", "ANTHROPIC_BASE_URL=" + api.URL, "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "DISABLE_AUTOUPDATER=1", "KONTEXT_PROBE_EVENTS=" + events}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("Claude: %v: %s", err, out)
			}
			observed, _ := os.ReadFile(events)
			counts := map[string]int{}
			for _, line := range strings.Split(strings.TrimSpace(string(observed)), "\n") {
				if line != "" {
					counts[line]++
				}
			}
			for _, event := range []string{"session-start", "user-prompt-submit", "pre-tool-use", "post-tool-use", "stop"} {
				if counts["hook "+event] != scenario.want {
					t.Fatalf("%s: got %v, want %d each", event, counts, scenario.want)
				}
			}
			t.Logf("hook invocation counts: %v", counts)
		})
	}
}

func claudeProbeAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		io.WriteString(w, `{"data":[],"has_more":false}`)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/count_tokens") {
		io.WriteString(w, `{"input_tokens":10}`)
		return
	}
	var request struct {
		Messages json.RawMessage `json:"messages"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	tool := !bytes.Contains(request.Messages, []byte(`"tool_result"`))
	reason := "end_turn"
	block := map[string]any{"type": "text", "text": ""}
	delta := map[string]any{"type": "text_delta", "text": "Local probe complete."}
	if tool {
		reason = "tool_use"
		block = map[string]any{"type": "tool_use", "id": "toolu_probe", "name": "Bash", "input": map[string]any{}}
		delta = map[string]any{"type": "input_json_delta", "partial_json": `{"command":"ls -la","description":"List isolated test directory"}`}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	for _, event := range []map[string]any{
		{"type": "message_start", "message": map[string]any{"id": "msg_probe", "type": "message", "role": "assistant", "model": "claude-sonnet-4-5", "content": []any{}, "stop_reason": nil, "stop_sequence": nil, "usage": map[string]int{"input_tokens": 10, "output_tokens": 0}}},
		{"type": "content_block_start", "index": 0, "content_block": block},
		{"type": "content_block_delta", "index": 0, "delta": delta},
		{"type": "content_block_stop", "index": 0},
		{"type": "message_delta", "delta": map[string]any{"stop_reason": reason, "stop_sequence": nil}, "usage": map[string]int{"output_tokens": 5}},
		{"type": "message_stop"},
	} {
		data, _ := json.Marshal(event)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event["type"], data)
	}
}
