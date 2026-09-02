package risk

import (
	"fmt"
	"testing"
)

func TestNormalizeHookEventClassifiesEveryCodexShellLikeBash(t *testing.T) {
	want := NormalizeHookEvent(HookEvent{Agent: "claude", ToolName: "Bash", ToolInput: map[string]any{"command": "git push --force origin main"}})
	for _, name := range []string{"shell", "unified_exec", "exec_command", "local_shell"} {
		got := NormalizeHookEvent(HookEvent{Agent: "codex", ToolName: name, ToolInput: map[string]any{"command": []any{"bash", "-lc", "git push --force origin main"}}})
		if got.Type != want.Type || fmt.Sprint(got.Signals) != fmt.Sprint(want.Signals) {
			t.Errorf("%s: type=%s signals=%v, want type=%s signals=%v", name, got.Type, got.Signals, want.Type, want.Signals)
		}
	}
}
