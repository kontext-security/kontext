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

// The handler must run for every Bash call, as the scan's Kontext hook set
// counts it: device wide, unconditional, synchronous, matching every tool.
func TestVerifyNeedsAKontextPreToolUseForEveryCall(t *testing.T) {
	for _, tc := range []struct {
		set  agentauthority.KontextHookSet
		want bool
	}{
		{agentauthority.KontextHookSet{State: "complete", MissingEvents: []string{}}, true},
		{agentauthority.KontextHookSet{State: "needs_update", MissingEvents: []string{"Stop"}}, true},
		{agentauthority.KontextHookSet{State: "needs_update", MissingEvents: []string{"PreToolUse"}}, false},
		{agentauthority.KontextHookSet{State: agentauthority.KontextHooksUnknown, MissingEvents: []string{}}, false},
	} {
		if got := coversPreToolUse(agentauthority.HookAgent{KontextHooks: tc.set}); got != tc.want {
			t.Fatalf("%+v: %v", tc.set, got)
		}
	}
}
