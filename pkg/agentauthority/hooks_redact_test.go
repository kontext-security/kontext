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
		"*.ts|.envrc":                  "*.ts|<redacted>",
		".AcmeBuyout":                  "<redacted>",
		"":                             "",
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

// A webhook's host can be its credential, and a plugin's metadata or an MCP
// server's name can hold a token by mistake: each is hidden.
func TestHookIdentityFieldsHideTokens(t *testing.T) {
	for raw, want := range map[string]string{
		"https://hooks.example.com/x":                "https://hooks.example.com",
		"https://eo1a2b3c4d5e6f7.m.pipedream.net/":   "https://<redacted>.m.pipedream.net",
		"https://abcdefghijklmnopqrstuvwxyz.example": "https://<redacted>.example",
		"https://api2.example.com:8443":              "https://api2.example.com:8443",
	} {
		if got := summaryURL(raw); got != want {
			t.Errorf("summaryURL(%q) = %q, want %q", raw, got, want)
		}
	}
	token := "npm_" + strings.Repeat("a1B2", 9)
	if got := hookField(token, 64); got != redacted {
		t.Fatalf("hookField(npm token) = %q", got)
	}
	if got := hookField("1.4.0", 64); got != "1.4.0" {
		t.Fatalf("hookField(version) = %q", got)
	}
}
