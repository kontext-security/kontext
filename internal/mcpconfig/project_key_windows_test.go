package mcpconfig

import (
	"encoding/json"
	"testing"

	"github.com/kontext-security/kontext/pkg/agentauthority/readers"
)

// Claude Code writes a project's key in ~/.claude.json with forward slashes
// on Windows too: C:/Users/name/dir for C:\Users\name\dir (seen with Claude
// Code 2.1.292). A session in that directory, or below it, belongs to it.
func TestProjectIsFoundByTheKeyClaudeCodeWrites(t *testing.T) {
	var root readers.ClaudeRoot
	if err := json.Unmarshal([]byte(`{"projects": {"C:/Users/name/dir": {}}}`), &root); err != nil {
		t.Fatal(err)
	}
	const project = `C:\Users\name\dir`
	for _, cwd := range []string{project, project + `\pkg`, "C:/Users/name/dir/pkg"} {
		if got := projectRoot(root, cwd); got != project {
			t.Errorf("projectRoot(%q) = %q, want %q", cwd, got, project)
		}
	}
	if got := projectRoot(root, `C:\Users\name\other`); got != "" {
		t.Errorf("projectRoot outside the project = %q, want none", got)
	}
}
