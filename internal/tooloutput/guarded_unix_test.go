//go:build !windows

package tooloutput

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// Compaction reads nothing of a call from the folders macOS guards: there,
// the daemon would make macOS ask the user for access. Named pipes stand in
// for the call's files and transcript, and any open of one would hang.
func TestNeverOpensGuardedPaths(t *testing.T) {
	enabled := privacyfolder.Enabled
	privacyfolder.Enabled = true
	t.Cleanup(func() { privacyfolder.Enabled = enabled })
	c := newTestCompactor(t, replace("kept\n[omitted]\n"))
	project := filepath.Join(c.home, "Documents", "app")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	pipe := func(name string) string {
		path := filepath.Join(project, name)
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Skipf("named pipes unavailable: %v", err)
		}
		return path
	}
	log, source, transcript := pipe("out.log"), pipe("main.go"), pipe("session.jsonl")

	bash := c.bash("cat out.log; sed -n 1,5p "+source+"; cd ~/Documents/app && head session.jsonl", bigText(80))
	bash.CWD, bash.TranscriptPath = project, transcript
	read := c.read(source, bigText(60), 1)
	read.ToolUseID, read.CWD, read.TranscriptPath = "toolu_read", project, transcript
	reread := hook.Event{SessionID: testSession, Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolUseID: "toolu_tail",
		CWD: project, TranscriptPath: transcript, ToolInput: map[string]any{"command": "tail " + log}}
	// Codex's session log says how the command exited; without it, the output
	// stays as it is.
	codex := hook.Event{SessionID: "codex-019a", Agent: "codex", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolUseID: "call_1",
		CWD: project, TranscriptPath: transcript, ToolInput: map[string]any{"command": "cat out.log"}, ToolResponse: map[string]any{"content": bigText(80)}}

	type compacted struct{ bash, codex map[string]any }
	done := make(chan compacted, 1)
	go func() {
		bashOutput := c.Compact(context.Background(), bash)
		c.Compact(context.Background(), read)
		c.Observe(context.Background(), reread)
		done <- compacted{bash: bashOutput, codex: c.Compact(context.Background(), codex)}
	}()
	select {
	case got := <-done:
		if got.bash == nil {
			t.Fatal("a Bash output from a Documents project was not compacted")
		}
		if got.codex != nil {
			t.Fatal("a Codex output was compacted without reading its session log")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("compaction opened a path in a guarded folder")
	}
	requests, _, _ := c.api.calls()
	if len(requests) != 2 || len(requests[0].Context.History) != 0 {
		t.Fatalf("requests = %d, history %+v: the transcript in Documents must not be read", len(requests), requests[0].Context.History)
	}
}
