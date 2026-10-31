package managedobserve

import (
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/tooloutput"
)

// An agent drops a hook's answer at the hook's timeout: the one Kontext
// installs must leave room for the PostToolUse answer and the compaction
// round trip after it.
func TestHookTimeoutsCoverCompaction(t *testing.T) {
	need := asyncHookWait + tooloutput.HookWait + 2*time.Second
	for agent, seconds := range map[string]int{"codex": codexmanaged.DefaultHookTimeout, "claude": claudemanaged.DefaultHookTimeout} {
		if timeout := time.Duration(seconds) * time.Second; timeout < need {
			t.Errorf("%s hook timeout = %v, want at least %v", agent, timeout, need)
		}
	}
}
