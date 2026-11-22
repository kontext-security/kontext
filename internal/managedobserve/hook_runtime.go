package managedobserve

import (
	"maps"
	"regexp"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

// HookVerifyCommandPrefix starts the Bash command `kontext hooks verify` asks
// Kontext's PreToolUse hook about. The command is a shell no-op, and the
// daemon denies it in every rollout mode: a deny that blocks nothing, which
// proves the deny path end to end. HookVerifyAckPrefix starts the second
// call, which confirms the deny reached the caller.
const (
	HookVerifyCommandPrefix = ": kontext-hooks-verify "
	HookVerifyAckPrefix     = ": kontext-hooks-verify-ack "
	// HookVerifyMarker is in both commands; the local runtime decodes an
	// event for the probe check only when its tool input holds it.
	HookVerifyMarker = "kontext-hooks-verify"
)

var (
	hookVerifyCommand = regexp.MustCompile(`^: kontext-hooks-verify ([0-9a-f]{32})$`)
	hookVerifyAck     = regexp.MustCompile(`^: kontext-hooks-verify-ack ([0-9a-f]{32})$`)
)

// The reasons the daemon's answers carry. The CLI requires them exactly, so
// a deny from anything else, an older daemon included, is no verification.
const (
	HookVerifyReason = "Kontext hook verification: this no-op command is always denied."
	// HookVerifyAckReason: the verification is recorded.
	HookVerifyAckReason = "Kontext hook verification: recorded."
	// HookVerifyNotRecordedReason: the probe was denied but not recorded,
	// because the hook inventory is off, the rollout is observe only, no hook
	// scan has run yet, or the probe expired.
	HookVerifyNotRecordedReason = "Kontext hook verification: not recorded."
)

// hookProbeTTL bounds the time between a probe and its acknowledgement, and
// maxHookProbes how many unacknowledged probes are kept.
const (
	hookProbeTTL  = 2 * time.Minute
	maxHookProbes = 4
)

func probeNonce(event hook.Event, pattern *regexp.Regexp) (string, bool) {
	if event.HookName != hook.HookPreToolUse || event.ToolName != "Bash" {
		return "", false
	}
	command, _ := event.ToolInput["command"].(string)
	m := pattern.FindStringSubmatch(command)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// IsHookVerifyEvent reports a PreToolUse event that is a verification probe
// or its acknowledgement: a Bash call whose command is exactly the no-op
// with a nonce.
func IsHookVerifyEvent(event hook.Event) bool {
	_, probe := probeNonce(event, hookVerifyCommand)
	_, ack := probeNonce(event, hookVerifyAck)
	return probe || ack
}

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
	// seen is when each of Kontext's handlers was first in a scan. An event
	// is evidence for a handler only if the handler was seen before it, so
	// a handler added later doesn't inherit what another one did.
	seen map[string]time.Time
	// last is the latest scan's Kontext PreToolUse handlers and agent
	// version, which a probe binds to.
	last        map[string]string
	lastVersion *string
	scanned     bool
	probes      map[string]hookVerification
	verify      *hookVerification
	// enabled reports the hook inventory on for the current enrolment.
	// While it is off, or unset, nothing is recorded. Set before the
	// runtime takes events.
	enabled func() bool
	// honoursDeny: the hook passes the daemon's enforce-stamped deny on to
	// the agent. Only then does a probe verify anything.
	honoursDeny bool
	// policyRevision names the policy deployment in force.
	policyRevision func() string
	// verified runs after a verification is recorded, so the hook scan
	// picks it up without waiting for its next tick.
	verified func()
}

type hookDecision struct {
	at       time.Time
	decision string
}

// hookVerification is an acknowledged probe, bound to the Kontext
// PreToolUse handlers and the agent version of the last scan before it.
type hookVerification struct {
	at             time.Time
	policyRevision string
	agentVersion   *string
	// contents holds the content fingerprint of each hook id at the probe.
	contents map[string]string
}

func newHookRuntime() *hookRuntime {
	r := &hookRuntime{now: time.Now}
	r.clear()
	return r
}

func (r *hookRuntime) clear() {
	r.invocations, r.decisions, r.seen = map[string]time.Time{}, map[string]hookDecision{}, map[string]time.Time{}
	r.last, r.lastVersion, r.scanned = map[string]string{}, nil, false
	r.probes, r.verify = map[string]hookVerification{}, nil
}

// reset forgets all evidence: the hook inventory went off, or the Mac moved
// to another workspace, and nothing seen before may count after.
func (r *hookRuntime) reset() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clear()
}

func (r *hookRuntime) on() bool { return r.enabled != nil && r.enabled() }

// intercept answers a verification probe or its acknowledgement with a
// deny. A probe is kept pending, bound to the last scan; the acknowledgement,
// which the CLI sends only after it read the probe's deny, records it. Every
// other event goes on to the policy.
func (r *hookRuntime) intercept(event hook.Event) (hook.Result, bool) {
	if r == nil || event.Agent != managedconfig.Agent {
		return hook.Result{}, false
	}
	deny := func(reason, code string) (hook.Result, bool) {
		return hook.Result{Decision: hook.DecisionDeny, Reason: reason, ReasonCode: code, Mode: "enforce"}, true
	}
	if nonce, ok := probeNonce(event, hookVerifyCommand); ok {
		revision := ""
		if r.policyRevision != nil {
			revision = r.policyRevision()
		}
		on := r.on()
		r.mu.Lock()
		defer r.mu.Unlock()
		now := r.now()
		maps.DeleteFunc(r.probes, func(_ string, p hookVerification) bool { return now.Sub(p.at) > hookProbeTTL })
		if r.honoursDeny && on && r.scanned && len(r.probes) < maxHookProbes {
			r.probes[nonce] = hookVerification{at: now, policyRevision: revision, agentVersion: r.lastVersion, contents: maps.Clone(r.last)}
		}
		return deny(HookVerifyReason, "hook_verification")
	}
	nonce, ok := probeNonce(event, hookVerifyAck)
	if !ok {
		return hook.Result{}, false
	}
	on := r.on()
	r.mu.Lock()
	probe, pending := r.probes[nonce]
	delete(r.probes, nonce)
	recorded := pending && on && r.now().Sub(probe.at) <= hookProbeTTL
	wake := r.verified
	if recorded {
		r.verify = &probe
	}
	r.mu.Unlock()
	if !recorded {
		return deny(HookVerifyNotRecordedReason, "hook_verification_not_recorded")
	}
	if wake != nil {
		wake()
	}
	return deny(HookVerifyAckReason, "hook_verification_recorded")
}

// evaluated records that the agent ran a hook for event, and for a
// PreToolUse what the policy answered. policy is false for an answer the
// policy didn't give, such as a fallback after a failure.
func (r *hookRuntime) evaluated(event hook.Event, result hook.Result, policy bool) {
	if r == nil || event.Agent != managedconfig.Agent || !r.on() {
		return
	}
	name := string(event.HookName)
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if now.After(r.invocations[name]) {
		r.invocations[name] = now
	}
	if event.HookName != hook.HookPreToolUse || !policy || result.FailedOpen {
		return
	}
	decision := string(result.Decision)
	if result.Mode == "observe" {
		decision = "observe"
	}
	switch decision {
	case "allow", "deny", "ask", "observe":
		if now.After(r.decisions[name].at) {
			r.decisions[name] = hookDecision{at: now, decision: decision}
		}
	}
}

// apply adds the runtime evidence to Kontext's own enabled hooks in a scan.
// Claude Code doesn't say which handler ran, so an event's evidence goes to
// each of Kontext's enabled handlers for it that was seen before the event.
func (r *hookRuntime) apply(agent *agentauthority.HookAgent) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	present := map[string]bool{}
	r.last, r.lastVersion, r.scanned = map[string]string{}, agent.AgentVersion, true
	for _, record := range agent.Hooks {
		if !kontextRunning(record) {
			continue
		}
		present[record.ID] = true
		if _, ok := r.seen[record.ID]; !ok {
			r.seen[record.ID] = now
		}
		if record.Event == string(hook.HookPreToolUse) {
			r.last[record.ID] = record.ContentFP
		}
	}
	maps.DeleteFunc(r.seen, func(id string, _ time.Time) bool { return !present[id] })
	format := func(t time.Time) *string {
		s := t.UTC().Format(time.RFC3339Nano)
		return &s
	}
	for i := range agent.Hooks {
		record := &agent.Hooks[i]
		if !kontextRunning(*record) {
			continue
		}
		since := r.seen[record.ID]
		evidence := &record.Evidence
		if at, ok := r.invocations[record.Event]; ok && !at.Before(since) {
			evidence.InvocationAt = format(at)
		}
		if d, ok := r.decisions[record.Event]; ok && !d.at.Before(since) {
			evidence.PolicyEvaluatedAt, evidence.PolicyDecision = format(d.at), &d.decision
		}
		if v := r.verify; v != nil {
			if content, ok := v.contents[record.ID]; ok && !v.at.Before(since) {
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

// policyRevision names the deployment the policy is evaluated from: the
// active one, else the last known good, in the current shape or the legacy
// one. None while no policy is active.
func policyRevision(snapshot cedarpolicy.Snapshot) string {
	if snapshot.State == cedarpolicy.StateDisabled || snapshot.State == cedarpolicy.StateNoActivePolicy {
		return ""
	}
	for _, d := range []*cedarpolicy.Deployment{snapshot.Deployment, snapshot.LastKnownGood} {
		if d != nil {
			return d.DeploymentIdentity
		}
	}
	for _, d := range []*cedarpolicy.LegacyDeployment{snapshot.LegacyDeployment, snapshot.LegacyLastKnownGood} {
		if d != nil {
			return d.DeploymentIdentity
		}
	}
	return ""
}
