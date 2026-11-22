package managedobserve

import (
	"regexp"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

// HookVerifyCommandPrefix starts the Bash command `kontext hooks verify` asks
// Kontext's PreToolUse hook about. The command is a shell no-op, and the
// daemon denies it in every rollout mode: a deny that blocks nothing, which
// proves the deny path end to end.
const HookVerifyCommandPrefix = ": kontext-hooks-verify "

var hookVerifyCommand = regexp.MustCompile(`^: kontext-hooks-verify [0-9a-f]{32}$`)

// IsHookVerifyEvent reports a PreToolUse event that is a verification
// probe: a Bash call whose command is exactly the no-op with a nonce.
func IsHookVerifyEvent(event hook.Event) bool {
	if event.HookName != hook.HookPreToolUse || event.ToolName != "Bash" {
		return false
	}
	command, _ := event.ToolInput["command"].(string)
	return hookVerifyCommand.MatchString(command)
}

// HookVerifyReason is the reason the probe's deny carries.
const HookVerifyReason = "Kontext hook verification: this no-op command is always denied."

// hookRuntime keeps the runtime evidence of Kontext's own Claude Code hooks
// (ADR-0011): when each event's hook last ran, the last policy decision, and
// the last verification. It holds times and decisions only, never content.
// The cloud keeps runtime times from moving back, so losing them on a
// restart costs nothing that was already sent.
type hookRuntime struct {
	mu          sync.Mutex
	now         func() time.Time
	invocations map[string]time.Time
	decisions   map[string]hookDecision
	verify      *hookVerification
	// honoursDeny: the hook passes the daemon's enforce-stamped deny on to
	// the agent. Only then does a probe verify anything.
	honoursDeny bool
	// policyRevision names the policy deployment in force.
	policyRevision func() string
	// verified runs after a verification probe is answered, so the hook
	// scan picks it up without waiting for its next tick.
	verified func()
}

type hookDecision struct {
	at       time.Time
	decision string
}

// hookVerification is a probe's result. Until the next scan binds it, it
// names no hook: the scan right after the probe records the content and
// agent version of the Kontext PreToolUse hooks it ran through.
type hookVerification struct {
	at             time.Time
	policyRevision string
	bound          bool
	agentVersion   *string
	// contents holds the content fingerprint of each hook id at binding.
	contents map[string]string
}

func newHookRuntime() *hookRuntime {
	return &hookRuntime{now: time.Now, invocations: map[string]time.Time{}, decisions: map[string]hookDecision{}}
}

// intercept answers a verification probe with a deny and records it. Every
// other event goes on to the policy.
func (r *hookRuntime) intercept(event hook.Event) (hook.Result, bool) {
	if r == nil || event.Agent != managedconfig.Agent || !IsHookVerifyEvent(event) {
		return hook.Result{}, false
	}
	revision := ""
	if r.policyRevision != nil {
		revision = r.policyRevision()
	}
	r.mu.Lock()
	wake := r.verified
	if r.honoursDeny {
		r.verify = &hookVerification{at: r.now(), policyRevision: revision}
	} else {
		wake = nil
	}
	r.mu.Unlock()
	if wake != nil {
		wake()
	}
	return hook.Result{Decision: hook.DecisionDeny, Reason: HookVerifyReason, ReasonCode: "hook_verification", Mode: "enforce"}, true
}

// evaluated records that the agent ran a hook for event, and for a
// PreToolUse what the policy answered.
func (r *hookRuntime) evaluated(event hook.Event, result hook.Result) {
	if r == nil || event.Agent != managedconfig.Agent {
		return
	}
	name := string(event.HookName)
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.invocations[name] = now
	if event.HookName != hook.HookPreToolUse || result.FailedOpen {
		return
	}
	decision := string(result.Decision)
	if result.Mode == "observe" {
		decision = "observe"
	}
	switch decision {
	case "allow", "deny", "ask", "observe":
		r.decisions[name] = hookDecision{at: now, decision: decision}
	}
}

// apply adds the runtime evidence to Kontext's own enabled hooks in a scan.
// Claude Code doesn't say which handler ran, so an event's evidence goes to
// each of Kontext's enabled handlers for it.
func (r *hookRuntime) apply(agent *agentauthority.HookAgent) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if v := r.verify; v != nil && !v.bound {
		v.bound, v.agentVersion, v.contents = true, agent.AgentVersion, map[string]string{}
		for _, record := range agent.Hooks {
			if kontextRunning(record) && record.Event == string(hook.HookPreToolUse) {
				v.contents[record.ID] = record.ContentFP
			}
		}
	}
	format := func(t time.Time) *string {
		s := t.UTC().Format(time.RFC3339Nano)
		return &s
	}
	for i := range agent.Hooks {
		record := &agent.Hooks[i]
		if !kontextRunning(*record) {
			continue
		}
		evidence := &record.Evidence
		if at, ok := r.invocations[record.Event]; ok {
			evidence.InvocationAt = format(at)
		}
		if d, ok := r.decisions[record.Event]; ok {
			evidence.PolicyEvaluatedAt, evidence.PolicyDecision = format(d.at), &d.decision
		}
		if v := r.verify; v != nil {
			if content, ok := v.contents[record.ID]; ok {
				var revision *string
				if v.policyRevision != "" {
					revision = &v.policyRevision
				}
				evidence.VerifiedAt = format(v.at)
				evidence.Verification = &agentauthority.HookVerification{AgentVersion: v.agentVersion, ContentFP: content, PolicyRevision: revision}
			}
		}
		evidence.Level = evidenceLevel(*evidence, record.ContentFP, agent.AgentVersion)
	}
}

// kontextRunning is one of Kontext's own handlers that Claude Code runs.
func kontextRunning(record agentauthority.HookRecord) bool {
	return record.Origin == agentauthority.HookOriginKontext && record.Enablement.State == "enabled"
}

// evidenceLevel is the highest level the evidence supports, as the cloud
// reads it: verified needs a verification of this content on this agent
// version.
func evidenceLevel(e agentauthority.HookEvidence, content string, agentVersion *string) string {
	verified := e.VerifiedAt != nil && e.Verification != nil && e.Verification.ContentFP == content &&
		equalVersion(e.Verification.AgentVersion, agentVersion)
	switch {
	case verified:
		return agentauthority.HookEvidenceEnforcementVerified
	case e.PolicyEvaluatedAt != nil:
		return agentauthority.HookEvidencePolicyEvaluated
	case e.InvocationAt != nil:
		return agentauthority.HookEvidenceInvocationObserved
	case e.ConfigCheckedAt != nil:
		return agentauthority.HookEvidenceConfigChecked
	}
	return agentauthority.HookEvidenceDiscovered
}

func equalVersion(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
