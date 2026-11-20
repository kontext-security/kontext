package agentauthority

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/pkg/agentauthority/readers"
)

// The pattern mirrors AUTHORITY_SECRET_PATTERN in kontext-cloud
// packages/shared authority.ts: every gh*_ prefix and Basic credentials.
func TestSecretPatternMatchesTheCloudsShapes(t *testing.T) {
	for _, value := range []string{"ghp_x", "gho_x", "ghu_x", "ghs_short1", "ghr_x", "github_pat_x", "curl -H Basic ZGVwbG95OnB3", "AUTH='basic ZGVwbG95OnB3'"} {
		if !secretPattern.MatchString(value) {
			t.Errorf("%q not flagged", value)
		}
	}
	for _, value := range []string{"ghx_short", "basic setup", "bash check-secrets.sh"} {
		if secretPattern.MatchString(value) {
			t.Errorf("%q flagged", value)
		}
	}
}

// A program spelled other than its cleaned path is never checked: the guard
// reads the cleaned path, the OS the spelled one.
func TestProgramMissingChecksOnlyCanonicalPaths(t *testing.T) {
	dir := t.TempDir()
	absent := filepath.Join(dir, "gone")
	if !programMissing(context.Background(), dir, absent) {
		t.Fatal("canonical absent path not reported")
	}
	if programMissing(context.Background(), dir, dir+"/x/../gone") {
		t.Fatal("non-canonical path checked")
	}
}

// The literal null is no settings file: reading it as empty would withdraw
// the file's hooks.
func TestNullSettingsAreMalformed(t *testing.T) {
	if _, err := readers.Hooks([]byte("null")); err == nil {
		t.Fatal("null read as settings")
	}
}

// A file event's matcher names files: only an extension or * stays.
func TestFileEventMatchersHideFileNames(t *testing.T) {
	for matcher, want := range map[string]string{
		"Acme-acquisition-targets.csv": "<redacted>",
		"*.ts|.envrc":                  "*.ts|.envrc",
		"*":                            "*",
	} {
		if got := safeEventMatcher("FileChanged", matcher); got != want {
			t.Errorf("%q = %q, want %q", matcher, got, want)
		}
	}
	if got := safeEventMatcher("PreToolUse", "Bash|Edit"); got != "Bash|Edit" {
		t.Errorf("tool matcher = %q", got)
	}
}

// An event name shaped like a token is a generator's mistake and never
// reported: the cloud stores event names verbatim.
func TestTokenShapedEventIsSkipped(t *testing.T) {
	h := newHookHome(t)
	event := "npm_" + strings.Repeat("a1", 16)
	h.write(filepath.Join(h.base, "settings.json"), map[string]any{"hooks": hooksOf(event, "", command("check.sh"))})
	agent, _ := h.scan()
	if len(agent.Hooks) != 0 {
		t.Fatalf("reported %+v", agent.Hooks)
	}
}
