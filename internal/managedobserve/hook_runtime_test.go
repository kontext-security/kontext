package managedobserve

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	guardhookruntime "github.com/kontext-security/kontext/internal/guard/hookruntime"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

func probeEvent(command string) hook.Event {
	return hook.Event{Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": command}}
}

func kontextRecord(id, event, content, origin, state string) agentauthority.HookRecord {
	return agentauthority.HookRecord{ID: id, Event: event, ContentFP: content, Origin: origin, Enablement: agentauthority.HookEnablement{State: state},
		Evidence: agentauthority.HookEvidence{Level: agentauthority.HookEvidenceConfigChecked, DiscoveredAt: "2026-11-22T10:00:00Z"}}
}

func testRuntime(at time.Time) *hookRuntime {
	r := newHookRuntime()
	r.now = func() time.Time { return at }
	r.honoursDeny = true
	r.enabled = func() bool { return true }
	r.policyRevision = func() string { return "dep_1" }
	return r
}

// verifyNow runs a probe and its acknowledgement, and returns the second
// answer's reason.
func verifyNow(t *testing.T, r *hookRuntime, nonce string) string {
	t.Helper()
	probe, ok := r.intercept(probeEvent(HookVerifyCommandPrefix + nonce))
	if !ok || probe.Reason != HookVerifyReason {
		t.Fatalf("probe %+v %v", probe, ok)
	}
	ack, ok := r.intercept(probeEvent(HookVerifyAckPrefix + nonce))
	if !ok || ack.Decision != hook.DecisionDeny {
		t.Fatalf("ack %+v %v", ack, ok)
	}
	return ack.Reason
}

// Only the exact no-op with a nonce is a probe, and only from Claude Code.
func TestHookVerifyProbeShape(t *testing.T) {
	nonce := strings.Repeat("ab", 16)
	r := testRuntime(time.Now())
	for _, tc := range []struct {
		event hook.Event
		probe bool
	}{
		{probeEvent(HookVerifyCommandPrefix + nonce), true},
		{probeEvent(HookVerifyAckPrefix + nonce), true},
		{probeEvent(HookVerifyAckPrefix + nonce + " "), false},
		{probeEvent(HookVerifyCommandPrefix + nonce + "; rm -rf x"), false},
		{probeEvent(HookVerifyCommandPrefix + "short"), false},
		{probeEvent("echo " + HookVerifyCommandPrefix + nonce), false},
		{hook.Event{Agent: "codex", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": HookVerifyCommandPrefix + nonce}}, false},
		{hook.Event{Agent: "claude", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": HookVerifyCommandPrefix + nonce}}, false},
	} {
		result, ok := r.intercept(tc.event)
		if ok != tc.probe {
			t.Fatalf("%+v: intercepted %v", tc.event, ok)
		}
		if ok && (result.Decision != hook.DecisionDeny || result.Mode != "enforce") {
			t.Fatalf("probe answer %+v", result)
		}
	}
}

// A verification binds to the Kontext PreToolUse handlers and agent version
// of the last scan before the probe, so a later change makes it an older
// result. It is recorded only once acknowledged.
func TestHookVerificationBindsAtTheProbe(t *testing.T) {
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	r := testRuntime(at)
	woke := 0
	r.verified = func() { woke++ }
	version := "2.1.329"
	scan := func(content, version string) agentauthority.HookAgent {
		return agentauthority.HookAgent{AgentVersion: &version, Hooks: []agentauthority.HookRecord{
			agentauthority.WithGuardsEveryBashCall(kontextRecord("hk_pre", "PreToolUse", content, agentauthority.HookOriginKontext, "enabled")),
			kontextRecord("hk_other", "PreToolUse", "fp_x", agentauthority.HookOriginSettings, "enabled"),
		}}
	}
	// No scan yet: nothing to bind to, so nothing is recorded.
	if reason := verifyNow(t, r, strings.Repeat("9", 32)); reason != HookVerifyNotRecordedReason || woke != 0 {
		t.Fatalf("before a scan: %q, woke %d", reason, woke)
	}
	first := scan("fp_a", version)
	r.apply(&first)
	// A probe that is never acknowledged records nothing.
	r.intercept(probeEvent(HookVerifyCommandPrefix + strings.Repeat("8", 32)))
	again := scan("fp_a", version)
	r.apply(&again)
	if again.Hooks[0].Evidence.VerifiedAt != nil || woke != 0 {
		t.Fatalf("an unacknowledged probe verified %+v", again.Hooks[0].Evidence)
	}
	nonce := strings.Repeat("0", 32)
	r.intercept(probeEvent(HookVerifyCommandPrefix + nonce))
	// The configuration changes between the probe and the next scan: the
	// verification stays with what the probe ran through.
	changed := scan("fp_b", version)
	r.apply(&changed)
	if reason, _ := r.intercept(probeEvent(HookVerifyAckPrefix + nonce)); reason.Reason != HookVerifyAckReason || woke != 1 {
		t.Fatalf("ack %+v, woke %d", reason, woke)
	}
	r.apply(&changed)
	if e := changed.Hooks[0].Evidence; e.Verification == nil || e.Verification.ContentFP != "fp_a" || e.Level == agentauthority.HookEvidenceEnforcementVerified {
		t.Fatalf("changed content kept the verification current: %+v", e)
	}
	back := scan("fp_a", version)
	r.apply(&back)
	pre := back.Hooks[0].Evidence
	if pre.VerifiedAt == nil || *pre.Verification.AgentVersion != version || *pre.Verification.PolicyRevision != "dep_1" || pre.Level != agentauthority.HookEvidenceEnforcementVerified {
		t.Fatalf("verified %+v %+v", pre, pre.Verification)
	}
	if back.Hooks[1].Evidence.VerifiedAt != nil {
		t.Fatal("a hook that isn't Kontext's own was verified")
	}
	upgraded := scan("fp_a", "2.2.0")
	r.apply(&upgraded)
	if e := upgraded.Hooks[0].Evidence; e.Level == agentauthority.HookEvidenceEnforcementVerified {
		t.Fatalf("an agent upgrade kept the verification current: %+v", e)
	}
	// An acknowledgement is good once.
	if reason, _ := r.intercept(probeEvent(HookVerifyAckPrefix + nonce)); reason.Reason != HookVerifyNotRecordedReason {
		t.Fatalf("replayed ack %+v", reason)
	}
}

// A probe expires if its acknowledgement comes too late.
func TestHookProbeExpires(t *testing.T) {
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	r := testRuntime(at)
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{agentauthority.WithGuardsEveryBashCall(kontextRecord("hk_pre", "PreToolUse", "fp", agentauthority.HookOriginKontext, "enabled"))}}
	r.apply(&agent)
	nonce := strings.Repeat("7", 32)
	r.intercept(probeEvent(HookVerifyCommandPrefix + nonce))
	r.now = func() time.Time { return at.Add(hookProbeTTL + time.Second) }
	if reason, _ := r.intercept(probeEvent(HookVerifyAckPrefix + nonce)); reason.Reason != HookVerifyNotRecordedReason {
		t.Fatalf("late ack %+v", reason)
	}
}

// Under a static observe posture the probe's deny never reaches the agent,
// and with the hook inventory off nothing is kept, so nothing is verified.
func TestObservePostureOrInventoryOffVerifiesNothing(t *testing.T) {
	for _, off := range []func(*hookRuntime){
		func(r *hookRuntime) { r.honoursDeny = false },
		func(r *hookRuntime) { r.enabled = func() bool { return false } },
	} {
		r := testRuntime(time.Now())
		agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{agentauthority.WithGuardsEveryBashCall(kontextRecord("hk_pre", "PreToolUse", "fp", agentauthority.HookOriginKontext, "enabled"))}}
		r.apply(&agent)
		off(r)
		if reason := verifyNow(t, r, strings.Repeat("1", 32)); reason != HookVerifyNotRecordedReason {
			t.Fatalf("recorded: %q", reason)
		}
		r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, hook.Result{Decision: hook.DecisionAllow}, true)
		agent.Hooks[0].Evidence = kontextRecord("", "", "", "", "").Evidence
		r.apply(&agent)
		if e := agent.Hooks[0].Evidence; e.VerifiedAt != nil || r.enabled() == false && e.InvocationAt != nil {
			t.Fatalf("%+v", e)
		}
	}
}

// A reset drops all evidence: nothing from before an opt-out or another
// workspace counts after it.
func TestHookRuntimeReset(t *testing.T) {
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	r := testRuntime(at)
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{agentauthority.WithGuardsEveryBashCall(kontextRecord("hk_pre", "PreToolUse", "fp", agentauthority.HookOriginKontext, "enabled"))}}
	r.apply(&agent)
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, hook.Result{Decision: hook.DecisionAllow}, true)
	verifyNow(t, r, strings.Repeat("2", 32))
	r.reset()
	agent.Hooks[0].Evidence = kontextRecord("", "", "", "", "").Evidence
	r.apply(&agent)
	if e := agent.Hooks[0].Evidence; e.VerifiedAt != nil || e.InvocationAt != nil || e.PolicyEvaluatedAt != nil {
		t.Fatalf("evidence survived a reset: %+v", e)
	}
}

// Invocations and decisions go to Kontext's own enabled handlers for the
// event, never to another hook or to one that isn't running.
func TestHookRuntimeEvidence(t *testing.T) {
	at := time.Date(2026, 11, 22, 11, 0, 0, 0, time.UTC)
	r := testRuntime(at)
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{
		kontextRecord("hk_start", "SessionStart", "fp1", agentauthority.HookOriginKontext, "enabled"),
		kontextRecord("hk_pre", "PreToolUse", "fp2", agentauthority.HookOriginKontext, "enabled"),
		kontextRecord("hk_off", "PreToolUse", "fp3", agentauthority.HookOriginKontext, "disabled"),
		kontextRecord("hk_user", "SessionStart", "fp4", agentauthority.HookOriginSettings, "enabled"),
		kontextRecord("hk_stop", "Stop", "fp5", agentauthority.HookOriginKontext, "enabled"),
	}}
	// Events before a handler is first seen aren't its evidence.
	r.now = func() time.Time { return at.Add(-2 * time.Second) }
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookStop}, hook.Result{Decision: hook.DecisionAllow}, true)
	r.now = func() time.Time { return at.Add(-time.Second) }
	r.apply(&agent)
	r.now = func() time.Time { return at }
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookSessionStart}, hook.Result{Decision: hook.DecisionAllow}, true)
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, guardhookruntime.ObserveResult(hook.Event{HookName: hook.HookPreToolUse}, hook.Result{Decision: hook.DecisionDeny, Reason: "nope"}), true)
	r.evaluated(hook.Event{Agent: "codex", HookName: hook.HookStop}, hook.Result{Decision: hook.DecisionAllow}, true)
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPostToolUse}, hook.Result{Decision: hook.DecisionAllow}, true)
	late := kontextRecord("hk_late", "PostToolUse", "fp6", agentauthority.HookOriginKontext, "enabled")
	agent.Hooks = append(agent.Hooks, late)
	r.now = func() time.Time { return at.Add(time.Second) }
	for i := range agent.Hooks {
		agent.Hooks[i].Evidence = kontextRecord("", "", "", "", "").Evidence
	}
	r.apply(&agent)
	if e := agent.Hooks[5].Evidence; e.InvocationAt != nil {
		t.Fatalf("a handler added after the event got its evidence: %+v", e)
	}
	agent.Hooks = agent.Hooks[:5]
	want := at.Format(time.RFC3339Nano)
	start, pre := agent.Hooks[0].Evidence, agent.Hooks[1].Evidence
	if start.InvocationAt == nil || *start.InvocationAt != want || start.PolicyEvaluatedAt != nil || start.Level != agentauthority.HookEvidenceInvocationObserved {
		t.Fatalf("session start %+v", start)
	}
	if pre.PolicyDecision == nil || *pre.PolicyDecision != "observe" || pre.Level != agentauthority.HookEvidencePolicyEvaluated {
		t.Fatalf("pre-tool-use %+v", pre)
	}
	for _, r := range agent.Hooks[2:] {
		if r.Evidence.InvocationAt != nil {
			t.Fatalf("%s got evidence %+v", r.ID, r.Evidence)
		}
	}

	// A failed-open answer, or a fallback after a failure, is an
	// invocation without a policy decision.
	later := at.Add(time.Minute)
	r.now = func() time.Time { return later }
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, hook.FailOpen("daemon away"), true)
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, hook.Result{Decision: hook.DecisionDeny}, false)
	// Times never move back.
	r.now = func() time.Time { return at }
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, hook.Result{Decision: hook.DecisionAllow}, true)
	agent.Hooks[1].Evidence = kontextRecord("", "", "", "", "").Evidence
	r.apply(&agent)
	if e := agent.Hooks[1].Evidence; *e.InvocationAt != later.Format(time.RFC3339Nano) || *e.PolicyEvaluatedAt != want {
		t.Fatalf("after fail-open %+v", e)
	}
}

// The daemon answers the probe with an enforce-stamped deny, and the probe
// never reaches the ledger.
func TestDaemonDeniesTheVerifyProbe(t *testing.T) {
	socketPath, dbPath, stop := startTestDaemon(t)
	client := localruntime.NewClient(socketPath)
	client.Timeout = testRuntimeTimeout
	result, err := client.Process(context.Background(), hook.Event{
		SessionID: "kontext-hooks-verify-probe",
		Agent:     "claude",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": HookVerifyCommandPrefix + strings.Repeat("c", 32)},
		CWD:       "/tmp/project",
	})
	if err != nil || result.Decision != hook.DecisionDeny || result.Mode != "enforce" || result.Reason != HookVerifyReason {
		t.Fatalf("probe = %+v, %v", result, err)
	}
	stop()
	store := openTestStore(t, dbPath)
	defer store.Close()
	if _, err := store.Session(context.Background(), "kontext-hooks-verify-probe"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("the probe reached the ledger, or the read failed: %v", err)
	}
}

// Under the observe posture a plain allow stays "allow"; only one the policy
// would have blocked is "observe".
func TestObservedAllowStaysAllow(t *testing.T) {
	at := time.Date(2026, 11, 22, 11, 0, 0, 0, time.UTC)
	r := testRuntime(at)
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{agentauthority.WithGuardsEveryBashCall(kontextRecord("hk_pre", "PreToolUse", "fp", agentauthority.HookOriginKontext, "enabled"))}}
	r.now = func() time.Time { return at.Add(-time.Second) }
	r.apply(&agent)
	r.now = func() time.Time { return at }
	pre := hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}
	r.evaluated(pre, guardhookruntime.ObserveResult(pre, hook.Result{Decision: hook.DecisionAllow}), true)
	r.apply(&agent)
	if d := agent.Hooks[0].Evidence.PolicyDecision; d == nil || *d != "allow" {
		t.Fatalf("decision %v", d)
	}
}

// With two Kontext handlers for an event, its evidence is no one's; a
// verification goes only to the handler that guards every Bash call.
func TestAmbiguousEvidenceIsNoOnes(t *testing.T) {
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	r := testRuntime(at.Add(-time.Second))
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{
		agentauthority.WithGuardsEveryBashCall(kontextRecord("hk_all", "PreToolUse", "fp1", agentauthority.HookOriginKontext, "enabled")),
		kontextRecord("hk_edit", "PreToolUse", "fp2", agentauthority.HookOriginKontext, "enabled"),
	}}
	r.apply(&agent)
	r.now = func() time.Time { return at }
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, hook.Result{Decision: hook.DecisionAllow}, true)
	if reason := verifyNow(t, r, strings.Repeat("3", 32)); reason != HookVerifyAckReason {
		t.Fatalf("ack %q", reason)
	}
	r.apply(&agent)
	all, edit := agent.Hooks[0].Evidence, agent.Hooks[1].Evidence
	if all.InvocationAt != nil || edit.InvocationAt != nil || all.PolicyEvaluatedAt != nil {
		t.Fatalf("ambiguous evidence credited: %+v %+v", all, edit)
	}
	if all.Level != agentauthority.HookEvidenceEnforcementVerified || edit.VerifiedAt != nil {
		t.Fatalf("verification %+v %+v", all, edit)
	}
}

// A scan with no handler guarding every Bash call gives a probe nothing to
// bind to.
func TestProbeNeedsAGuardingHandler(t *testing.T) {
	r := testRuntime(time.Now())
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{kontextRecord("hk_edit", "PreToolUse", "fp", agentauthority.HookOriginKontext, "enabled")}}
	r.apply(&agent)
	if reason := verifyNow(t, r, strings.Repeat("4", 32)); reason != HookVerifyNotRecordedReason {
		t.Fatalf("recorded %q", reason)
	}
}

// A new policy deployment makes the verification an older result, and an
// earlier probe acknowledged late never replaces a later one.
func TestVerificationFollowsPolicyAndOrder(t *testing.T) {
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	r := testRuntime(at)
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{agentauthority.WithGuardsEveryBashCall(kontextRecord("hk_pre", "PreToolUse", "fp", agentauthority.HookOriginKontext, "enabled"))}}
	r.now = func() time.Time { return at.Add(-time.Minute) }
	r.apply(&agent)
	first, second := strings.Repeat("5", 32), strings.Repeat("6", 32)
	r.now = func() time.Time { return at }
	r.intercept(probeEvent(HookVerifyCommandPrefix + first))
	r.now = func() time.Time { return at.Add(time.Second) }
	r.policyRevision = func() string { return "dep_2" }
	r.intercept(probeEvent(HookVerifyCommandPrefix + second))
	r.intercept(probeEvent(HookVerifyAckPrefix + second))
	r.intercept(probeEvent(HookVerifyAckPrefix + first))
	r.apply(&agent)
	e := agent.Hooks[0].Evidence
	if e.Verification == nil || *e.Verification.PolicyRevision != "dep_2" || e.Level != agentauthority.HookEvidenceEnforcementVerified {
		t.Fatalf("%+v %+v", e, e.Verification)
	}
	r.policyRevision = func() string { return "dep_3" }
	r.apply(&agent)
	if e := agent.Hooks[0].Evidence; e.Level == agentauthority.HookEvidenceEnforcementVerified {
		t.Fatalf("a new deployment kept the verification current: %+v", e)
	}
}

// An answer Cedar didn't evaluate, or one after an engine error, is no
// policy evaluation.
func TestPolicyEvaluated(t *testing.T) {
	cedar := func(state cedareval.EvaluationState, errors int) hook.Result {
		return hook.WithMetadata(hook.Result{Decision: hook.DecisionAllow}, risk.RiskDecision{Cedar: &risk.CedarEvidence{Mapping: cedareval.DecisionMapping{EvaluationState: state}, EngineErrorCount: errors}})
	}
	for _, tc := range []struct {
		result hook.Result
		want   bool
	}{
		{hook.Result{Decision: hook.DecisionAllow}, true},
		{cedar(cedareval.EvaluationStateEvaluated, 0), true},
		{cedar(cedareval.EvaluationStateEvaluated, 1), false},
		{cedar(cedareval.EvaluationStateNotEvaluated, 0), false},
		{cedar(cedareval.EvaluationStateFailed, 0), false},
	} {
		if got := policyEvaluated(tc.result); got != tc.want {
			t.Errorf("%+v: %v", tc.result.Metadata(), got)
		}
	}
}

// An event that came while two handlers shared it stays no one's: removing
// one of them later doesn't hand the event to the other.
func TestEvidenceStaysWithTheHandlersOfItsTime(t *testing.T) {
	at := time.Date(2026, 11, 22, 11, 0, 0, 0, time.UTC)
	r := testRuntime(at)
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{
		kontextRecord("hk_bash", "PreToolUse", "fp1", agentauthority.HookOriginKontext, "enabled"),
		kontextRecord("hk_edit", "PreToolUse", "fp2", agentauthority.HookOriginKontext, "enabled"),
	}}
	r.now = func() time.Time { return at.Add(-time.Second) }
	r.apply(&agent)
	r.now = func() time.Time { return at }
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, hook.Result{Decision: hook.DecisionAllow}, true)
	agent.Hooks = agent.Hooks[1:]
	agent.Hooks[0].Evidence = kontextRecord("", "", "", "", "").Evidence
	r.now = func() time.Time { return at.Add(time.Second) }
	r.apply(&agent)
	if e := agent.Hooks[0].Evidence; e.InvocationAt != nil || e.PolicyEvaluatedAt != nil {
		t.Fatalf("the surviving handler took an event it may not have run: %+v", e)
	}
	// The next event is its own.
	r.now = func() time.Time { return at.Add(2 * time.Second) }
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, hook.Result{Decision: hook.DecisionAllow}, true)
	r.apply(&agent)
	if e := agent.Hooks[0].Evidence; e.InvocationAt == nil || e.PolicyEvaluatedAt == nil {
		t.Fatalf("a sole handler's event wasn't credited: %+v", e)
	}
}
