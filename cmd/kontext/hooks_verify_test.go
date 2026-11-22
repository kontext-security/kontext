package main

import (
	"testing"

	"github.com/kontext-security/kontext/pkg/agentauthority"
)

// Only a deny counts, and only its reason is read: a hook with no decision,
// an allow or a crash is no deny, and stderr only counts with exit code 2.
func TestReadProbeAnswer(t *testing.T) {
	for _, tc := range []struct {
		stdout string
		exit   int
		stderr string
		reason string
	}{
		{`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"x"}}`, 0, "", "x"},
		{`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"x"}}`, 0, "", probeAnswerMissing},
		{`{"hookSpecificOutput":{"hookEventName":"PostToolUse","permissionDecision":"deny","permissionDecisionReason":"x"}}`, 0, "", probeAnswerMissing},
		{"", 2, "blocked\n", "blocked"},
		{`{"suppressOutput":true}`, 0, "managed policy daemon unavailable at /Users/FAKE", probeAnswerMissing},
		{`{"hookSpecificOutput":{"permissionDecision":"allow"}}`, 0, "", probeAnswerMissing},
		{`{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"x"}}`, 1, "", probeAnswerMissing},
		{"not json", 1, "", probeAnswerMissing},
	} {
		if got := readProbeAnswer([]byte(tc.stdout), tc.exit, []byte(tc.stderr)); got != tc.reason {
			t.Fatalf("%q exit %d: %q", tc.stdout, tc.exit, got)
		}
	}
}

// Without a handler that guards every Bash call there is nothing to verify;
// which handlers do is the scan's to say (TestGuardsEveryBashCall).
func TestVerifyNeedsAHandlerForEveryBashCall(t *testing.T) {
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{{Event: "PreToolUse", Origin: agentauthority.HookOriginKontext, Enablement: agentauthority.HookEnablement{State: "enabled"}}}}
	if guardsEveryBashCall(agent) {
		t.Fatal("a record not from a scan guards nothing")
	}
}
