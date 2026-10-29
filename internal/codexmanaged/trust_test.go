package codexmanaged

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Hashes Codex 0.165 saved after trusting the template for
// /opt/homebrew/bin/kontext in /hooks. They pin the identity Codex hashes:
// event label, matcher only where the event uses one, normalized timeout,
// compact sorted JSON without HTML escaping.
var codexTrustedHashes = map[string]string{
	"pre_tool_use":       "sha256:3fb17ca4bc5d5442e2001ac26cff40bd9551ffa01c031e0e07da97bd1518ab6d",
	"post_tool_use":      "sha256:78cd2df2d9f321f271c39f8312e973c9f03cefd21a3efb02be7efa10f49b0615",
	"session_start":      "sha256:bd02c5c30eb90cd88ce8df7d45b80663c4f44b86af5743dcc582bbc5155e52a2",
	"user_prompt_submit": "sha256:4dd5b7ee023876a6f96a298f913182898c88b5de473183167f2dcf4da444c77d",
	"stop":               "sha256:fa8ab0488c932c615fa2c1f833da5ba875de8f08ed93f22ea12575f2d3d6f670",
}

func TestUntrustedHooks(t *testing.T) {
	all := []string{"post_tool_use", "pre_tool_use", "session_start", "stop", "user_prompt_submit"}
	for _, tc := range []struct {
		name, binary, extra string
		trust               bool
		want                []string
	}{
		{name: "trusted in /hooks", binary: "/opt/homebrew/bin/kontext", trust: true},
		{name: "never trusted", binary: "/opt/homebrew/bin/kontext", want: all},
		// The binary moved (Kontext.app to Homebrew): the old trust no longer matches.
		{name: "trusted for another binary", binary: "/Applications/Kontext.app/Contents/MacOS/kontext", trust: true, want: all},
		{name: "turned off in /hooks", binary: "/opt/homebrew/bin/kontext", trust: true, extra: "enabled = false\n", want: []string{"stop"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			hooks := filepath.Join(dir, "hooks.json")
			data, err := TemplateJSON(tc.binary)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(hooks, data, 0o600); err != nil {
				t.Fatal(err)
			}
			var config strings.Builder
			config.WriteString("[features]\nhooks = true\n")
			if tc.trust {
				for label, hash := range codexTrustedHashes {
					fmt.Fprintf(&config, "\n[hooks.state.%q]\ntrusted_hash = %q\n", hooks+":"+label+":0:0", hash)
					if label == "stop" {
						config.WriteString(tc.extra)
					}
				}
			}
			configPath := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(configPath, []byte(config.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := UntrustedHooks(hooks, configPath)
			if err != nil || !reflect.DeepEqual(got, tc.want) && len(got)+len(tc.want) > 0 {
				t.Fatalf("UntrustedHooks = %v, %v; want %v", got, err, tc.want)
			}
		})
	}
}

// Fields Codex hashes only for some events, and strings serde_json writes
// differently from Go. Expected values come from a serde-equivalent encoder
// (sorted keys, compact, no ASCII escaping); the stop value is Codex's own.
func TestHookHashMatchesCodex(t *testing.T) {
	pre := map[string]any{"type": "command", "command": "'/opt/homebrew/bin/kontext' hook --agent 'codex' 'pre-tool-use'", "timeout": float64(20)}
	with := func(key string, value any) map[string]any {
		h := map[string]any{key: value}
		for k, v := range pre {
			h[k] = v
		}
		return h
	}
	empty := ""
	for _, tc := range []struct {
		name, label string
		matcher     *string
		handler     map[string]any
		want        string
	}{
		{name: "stop ignores additionalContextLimit", label: "stop", matcher: &empty, handler: map[string]any{
			"type": "command", "command": "'/opt/homebrew/bin/kontext' hook --agent 'codex' 'stop'", "timeout": float64(20), "additionalContextLimit": float64(1000),
		}, want: codexTrustedHashes["stop"]},
		{name: "pre-tool-use keeps additionalContextLimit", label: "pre_tool_use", matcher: &empty, handler: with("additionalContextLimit", float64(1000)),
			want: "sha256:32407f907945f0ad15046b43c11eaefb4bf1578994db4772983f7520bacd85f2"},
		{name: "line separators and an escaped backslash", label: "pre_tool_use", matcher: &empty, handler: with("statusMessage", "a b \\u2029 c"),
			want: "sha256:607bd3e4f21df9e47cf08b9bba0c3bf2b7ba90defc981de44f29ec40dcb0c4e4"},
		{name: "adjacent line separators", label: "pre_tool_use", matcher: &empty, handler: with("statusMessage", "  "),
			want: "sha256:4572b298a4dd320e45ad42fb3cda4cc901a63103291e309dffbb510a3704c12b"},
	} {
		if got := hookHash(tc.label, tc.matcher, tc.handler); got != tc.want {
			t.Errorf("%s: hookHash = %s, want %s", tc.name, got, tc.want)
		}
	}
}

// Codex resolves a symlinked CODEX_HOME before it builds the trust key.
func TestUntrustedHooksResolvesCodexHome(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "codex-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CODEX_HOME", link)
	data, err := TemplateJSON("/opt/homebrew/bin/kontext")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "hooks.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}
	var config strings.Builder
	for label, hash := range codexTrustedHashes {
		fmt.Fprintf(&config, "[hooks.state.%q]\ntrusted_hash = %q\n", filepath.Join(resolved, "hooks.json")+":"+label+":0:0", hash)
	}
	if err := os.WriteFile(filepath.Join(real, "config.toml"), []byte(config.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := UntrustedHooks(filepath.Join(link, "hooks.json"), filepath.Join(link, "config.toml"))
	if err != nil || len(got) != 0 {
		t.Fatalf("UntrustedHooks = %v, %v; want all trusted", got, err)
	}
}
