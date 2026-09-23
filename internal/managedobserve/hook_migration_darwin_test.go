package managedobserve

import (
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/agenthooks"
)

func TestClaudeHookApprovalScriptCompilesAndPreservesLiteralArguments(t *testing.T) {
	// Compile the actual approval script without opening a dialog. Then use
	// AppleScript's return command to verify both quoting layers without ever
	// executing the adversarial path strings or asking for root in the tests.
	binary := `/tmp/with spaces/'"\$(touch SHOULD_NOT_EXIST);/kontext`
	script := claudeHookApprovalScript(binary, binary, "abc123")
	if out, err := exec.Command("/usr/bin/osacompile", "-o", filepath.Join(t.TempDir(), "probe.scpt"), "-e", script).CombinedOutput(); err != nil {
		t.Fatalf("compile approval script: %v: %s", err, out)
	}
	expression := strings.TrimPrefix(script, "do shell script ")
	expression = strings.Split(expression, " with administrator privileges")[0]
	out, err := exec.Command("/usr/bin/osascript", "-e", "return "+expression).Output()
	if err != nil {
		t.Fatal(err)
	}
	args, ok := agenthooks.SplitLiteralCommand(strings.TrimSpace(string(out)))
	want := []string{binary, "hooks", "refresh-claude", "--binary", binary, "--expected-sha256", "abc123"}
	if !ok || !reflect.DeepEqual(args, want) {
		t.Fatalf("arguments changed: %q want %q", args, want)
	}
}
