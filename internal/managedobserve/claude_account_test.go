package managedobserve

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClaudeAccountID(t *testing.T) {
	const fromConfig = "0f8fad5b-d9cb-469f-a165-70867728950e"
	const fromSession = "7c9e6679-7425-40de-944b-e07fc1f90ae7"
	for name, tc := range map[string]struct {
		session string
		off     string
		want    string
	}{
		"a laptop reads Claude's config":          {want: fromConfig},
		"a hosted session's environment wins":     {session: "7C9E6679-7425-40DE-944B-E07FC1F90AE7", want: fromSession},
		"a malformed environment value is unused": {session: "not-an-account", want: fromConfig},
		"the switch turns reporting off":          {session: fromSession, off: "1", want: ""},
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("CLAUDE_CONFIG_DIR", "")
			t.Setenv(envClaudeAccount, tc.session)
			t.Setenv(envNoClaudeAccount, tc.off)
			config := `{"oauthAccount": {"accountUuid": "` + fromConfig + `"}}`
			if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(config), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := claudeAccountID(); got != tc.want {
				t.Fatalf("claudeAccountID() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClaudeAccountIDIsEmptyInAHostedSessionWithoutOne(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv(envClaudeAccount, "")
	t.Setenv(envNoClaudeAccount, "")
	if got := claudeAccountID(); got != "" {
		t.Fatalf("claudeAccountID() = %q, want empty with no environment value and no config", got)
	}
}
