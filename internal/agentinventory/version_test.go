package agentinventory

import "testing"

func TestParseVersion(t *testing.T) {
	for output, want := range map[string]string{
		"2.1.300 (Claude Code)\n":   "2.1.300",
		"codex-cli 0.162.1\n":       "0.162.1",
		"2026.10.22-27dcf5f\n":      "2026.10.22-27dcf5f",
		"3.21.13":                   "3.21.13",
		"Usage: gemini [options]\n": "",
		"version 7\n":               "",
	} {
		if got := parseVersion(output); got != want {
			t.Errorf("parseVersion(%q) = %q, want %q", output, got, want)
		}
	}
}
