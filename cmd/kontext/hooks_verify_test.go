package main

import (
	"strings"
	"testing"

	"github.com/kontext-security/kontext/pkg/agentauthority"
)

// Only a deny counts: a hook with no decision, an allow or a crash leaves
// the probe unverified.
func TestReadProbeAnswer(t *testing.T) {
	for _, tc := range []struct {
		stdout string
		exit   int
		stderr string
		denied bool
		reason string
	}{
		{`{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"x"}}`, 0, "", true, "deny"},
		{"", 2, "blocked", true, "exit code 2"},
		{`{"suppressOutput":true}`, 0, "managed policy daemon unavailable\nmore", false, "no decision: managed policy daemon unavailable"},
		{`{"hookSpecificOutput":{"permissionDecision":"allow"}}`, 0, "", false, "answered allow"},
		{"not json", 1, "", false, "no decision, exit code 1"},
	} {
		denied, reason, err := readProbeAnswer([]byte(tc.stdout), tc.exit, strings.NewReader(tc.stderr))
		if err != nil || denied != tc.denied || reason != tc.reason {
			t.Fatalf("%q exit %d: %v %q %v", tc.stdout, tc.exit, denied, reason, err)
		}
	}
}

func TestVerifyNeedsARunningKontextPreToolUse(t *testing.T) {
	record := func(event, origin, state string) agentauthority.HookRecord {
		return agentauthority.HookRecord{Event: event, Origin: origin, Enablement: agentauthority.HookEnablement{State: state}}
	}
	for _, tc := range []struct {
		hooks []agentauthority.HookRecord
		want  bool
	}{
		{[]agentauthority.HookRecord{record("PreToolUse", agentauthority.HookOriginKontext, "enabled")}, true},
		{[]agentauthority.HookRecord{record("PreToolUse", agentauthority.HookOriginKontext, "disabled")}, false},
		{[]agentauthority.HookRecord{record("PreToolUse", agentauthority.HookOriginSettings, "enabled")}, false},
		{[]agentauthority.HookRecord{record("Stop", agentauthority.HookOriginKontext, "enabled")}, false},
	} {
		if got := runsKontextPreToolUse(agentauthority.HookAgent{Hooks: tc.hooks}); got != tc.want {
			t.Fatalf("%+v: %v", tc.hooks, got)
		}
	}
}
