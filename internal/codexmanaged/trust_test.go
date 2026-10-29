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
