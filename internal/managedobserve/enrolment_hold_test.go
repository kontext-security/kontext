package managedobserve

import (
	"io"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/guard/app/server"
	"github.com/kontext-security/kontext/internal/hook"
)

type fixedSnapshots cedarpolicy.State

func (s fixedSnapshots) Current() cedarpolicy.Snapshot {
	return cedarpolicy.Snapshot{State: cedarpolicy.State(s)}
}

func TestEnrolmentHoldOnlyWhileAPolicyCouldBlockAndIsMissing(t *testing.T) {
	pre := hook.Event{HookName: hook.HookPreToolUse}
	fresh := time.Now()
	for _, tc := range []struct {
		name        string
		started     time.Time
		wait        time.Duration
		enforcement server.CedarEnforcementSource
		state       cedarpolicy.State
		event       hook.Event
		holds       bool
	}{
		{"fresh, enforce, unenrolled", fresh, 3 * time.Second, server.CedarEnforcementStatic, cedarpolicy.StatePrincipalUnavailable, pre, true},
		{"fresh, remote, no fetch yet", fresh, 3 * time.Second, server.CedarEnforcementRemote, "", pre, true},
		{"observe", fresh, 3 * time.Second, server.CedarEnforcementOff, cedarpolicy.StatePrincipalUnavailable, pre, false},
		{"restart with a cached policy", fresh, 3 * time.Second, server.CedarEnforcementRemote, cedarpolicy.StateSuccess, pre, false},
		{"cloud unreachable after a fetch", fresh, 3 * time.Second, server.CedarEnforcementRemote, cedarpolicy.StateUnavailable, pre, false},
		{"past the wait", fresh.Add(-4 * time.Second), 3 * time.Second, server.CedarEnforcementStatic, cedarpolicy.StatePrincipalUnavailable, pre, false},
		{"switched off", fresh, 0, server.CedarEnforcementStatic, cedarpolicy.StatePrincipalUnavailable, pre, false},
		{"prompt submit", fresh, 3 * time.Second, server.CedarEnforcementStatic, cedarpolicy.StatePrincipalUnavailable, hook.Event{HookName: hook.HookUserPromptSubmit}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hold := enrolmentHold(tc.started, tc.wait, tc.enforcement, fixedSnapshots(tc.state))(tc.event)
			if (hold > 0) != tc.holds {
				t.Fatalf("hold = %v, want holding %v", hold, tc.holds)
			}
			if hold > tc.wait {
				t.Fatalf("hold = %v, longer than the wait %v", hold, tc.wait)
			}
		})
	}
}

func TestEnrolmentWaitOverride(t *testing.T) {
	quiet := diagnostic.New(io.Discard, false)
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"", defaultEnrolmentWait},
		{"0", 0},
		{"1500ms", 1500 * time.Millisecond},
		{"10s", maxPolicyHold},
		{"-1s", defaultEnrolmentWait},
		{"soon", defaultEnrolmentWait},
	} {
		t.Setenv(enrolmentWaitEnv, tc.value)
		if got := enrolmentWait(quiet); got != tc.want {
			t.Fatalf("%s=%q: wait = %v, want %v", enrolmentWaitEnv, tc.value, got, tc.want)
		}
	}
}
