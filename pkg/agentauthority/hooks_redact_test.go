package agentauthority

import "testing"

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
