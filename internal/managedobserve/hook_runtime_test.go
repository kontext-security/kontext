package managedobserve

import (
	"context"
	"strings"
	"testing"
	"time"

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
	r.policyRevision = func() string { return "dep_1" }
	return r
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

// A probe's verification binds to the content and agent version the next
// scan reads, so a later change makes it an older result.
func TestHookVerificationBindsToTheNextScan(t *testing.T) {
	at := time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	r := testRuntime(at)
	woke := 0
	r.verified = func() { woke++ }
	if _, ok := r.intercept(probeEvent(HookVerifyCommandPrefix + strings.Repeat("0", 32))); !ok || woke != 1 {
		t.Fatalf("intercepted %v, woke %d", ok, woke)
	}
	version := "2.1.329"
	scan := func(content, version string) agentauthority.HookAgent {
		return agentauthority.HookAgent{AgentVersion: &version, Hooks: []agentauthority.HookRecord{
			kontextRecord("hk_pre", "PreToolUse", content, agentauthority.HookOriginKontext, "enabled"),
			kontextRecord("hk_other", "PreToolUse", "fp_x", agentauthority.HookOriginSettings, "enabled"),
		}}
	}
	first := scan("fp_a", version)
	r.apply(&first)
	pre := first.Hooks[0].Evidence
	if pre.VerifiedAt == nil || pre.Verification == nil || pre.Verification.ContentFP != "fp_a" || *pre.Verification.AgentVersion != version || *pre.Verification.PolicyRevision != "dep_1" || pre.Level != agentauthority.HookEvidenceEnforcementVerified {
		t.Fatalf("verified %+v %+v", pre, pre.Verification)
	}
	if first.Hooks[1].Evidence.VerifiedAt != nil {
		t.Fatal("a hook that isn't Kontext's own was verified")
	}

	changed := scan("fp_b", version)
	r.apply(&changed)
	if e := changed.Hooks[0].Evidence; e.Verification == nil || e.Verification.ContentFP != "fp_a" || e.Level == agentauthority.HookEvidenceEnforcementVerified {
		t.Fatalf("changed content kept the verification current: %+v", e)
	}
	upgraded := scan("fp_a", "2.2.0")
	r.apply(&upgraded)
	if e := upgraded.Hooks[0].Evidence; e.Level == agentauthority.HookEvidenceEnforcementVerified {
		t.Fatalf("an agent upgrade kept the verification current: %+v", e)
	}
}

// Under a static observe posture the probe's deny never reaches the agent,
// so nothing is verified.
func TestObservePostureVerifiesNothing(t *testing.T) {
	r := testRuntime(time.Now())
	r.honoursDeny = false
	r.intercept(probeEvent(HookVerifyCommandPrefix + strings.Repeat("1", 32)))
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{kontextRecord("hk_pre", "PreToolUse", "fp", agentauthority.HookOriginKontext, "enabled")}}
	r.apply(&agent)
	if agent.Hooks[0].Evidence.VerifiedAt != nil {
		t.Fatalf("%+v", agent.Hooks[0].Evidence)
	}
}

// Invocations and decisions go to Kontext's own enabled handlers for the
// event, never to another hook or to one that isn't running.
func TestHookRuntimeEvidence(t *testing.T) {
	at := time.Date(2026, 11, 22, 11, 0, 0, 0, time.UTC)
	r := testRuntime(at)
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookSessionStart}, hook.Result{Decision: hook.DecisionAllow})
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, hook.Result{Decision: hook.DecisionDeny, Mode: "observe"})
	r.evaluated(hook.Event{Agent: "codex", HookName: hook.HookStop}, hook.Result{Decision: hook.DecisionAllow})
	agent := agentauthority.HookAgent{Hooks: []agentauthority.HookRecord{
		kontextRecord("hk_start", "SessionStart", "fp1", agentauthority.HookOriginKontext, "enabled"),
		kontextRecord("hk_pre", "PreToolUse", "fp2", agentauthority.HookOriginKontext, "enabled"),
		kontextRecord("hk_off", "PreToolUse", "fp3", agentauthority.HookOriginKontext, "disabled"),
		kontextRecord("hk_user", "SessionStart", "fp4", agentauthority.HookOriginSettings, "enabled"),
		kontextRecord("hk_stop", "Stop", "fp5", agentauthority.HookOriginKontext, "enabled"),
	}}
	r.apply(&agent)
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

	// A failed-open answer is an invocation without a policy decision.
	later := at.Add(time.Minute)
	r.now = func() time.Time { return later }
	r.evaluated(hook.Event{Agent: "claude", HookName: hook.HookPreToolUse}, hook.FailOpen("daemon away"))
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
	if _, err := store.Session(context.Background(), "kontext-hooks-verify-probe"); err == nil {
		t.Fatal("the probe opened a session in the ledger")
	}
}
