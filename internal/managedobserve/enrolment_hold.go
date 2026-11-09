package managedobserve

import (
	"os"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/guard/app/server"
	"github.com/kontext-security/kontext/internal/hook"
)

// defaultEnrolmentWait is how long after daemon start a PreToolUse call may
// be held until the policy arrives (ENG-939). After it, a call is decided
// with what the daemon has, which allows while no policy is there.
const defaultEnrolmentWait = 3 * time.Second

// enrolmentWaitEnv overrides defaultEnrolmentWait with a Go duration such as
// "1500ms", at most maxPolicyHold, which is as long as a hook will wait;
// "0" holds nothing.
const enrolmentWaitEnv = "KONTEXT_ENROLMENT_WAIT"

// enrolmentWait reads the override, keeping the default for an unset or
// unreadable value and the cap for a longer one, and saying so for both.
func enrolmentWait(diag diagnostic.Logger) time.Duration {
	raw := strings.TrimSpace(os.Getenv(enrolmentWaitEnv))
	if raw == "" {
		return defaultEnrolmentWait
	}
	if raw == "0" {
		return 0
	}
	wait, err := time.ParseDuration(raw)
	if err != nil || wait < 0 {
		diag.Printf("%s=%q is not a duration of zero or more; holding up to %s\n", enrolmentWaitEnv, raw, defaultEnrolmentWait)
		return defaultEnrolmentWait
	}
	if wait > maxPolicyHold {
		diag.Printf("%s=%q is longer than a hook waits; holding up to %s\n", enrolmentWaitEnv, raw, maxPolicyHold)
		return maxPolicyHold
	}
	return wait
}

// enrolmentHold says how long a PreToolUse call may be held: only where a
// policy can block (enforcement static or remote), only while the endpoint
// awaits enrolment, and only until wait after daemon start.
func enrolmentHold(started time.Time, wait time.Duration, enforcement server.CedarEnforcementSource, policies cedarpolicy.SnapshotProvider) func(hook.Event) time.Duration {
	return func(event hook.Event) time.Duration {
		if wait <= 0 || enforcement == server.CedarEnforcementOff || policies == nil || event.HookName != hook.HookPreToolUse {
			return 0
		}
		// The clock first: past the wait, which is every call after the first
		// seconds, this costs no cache read.
		remaining := time.Until(started.Add(wait))
		if remaining <= 0 || !cedarpolicy.AwaitingEnrolment(policies.Current().State) {
			return 0
		}
		return remaining
	}
}
