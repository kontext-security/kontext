package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/promptpolicy"
	"github.com/kontext-security/kontext/internal/sessionpolicy"
)

type promptTestDeriver struct{}

func (promptTestDeriver) Put(context.Context, promptpolicy.Request) (promptpolicy.Bundle, error) {
	return promptpolicy.Bundle{}, errors.New("unexpected generation")
}

type promptTestParents struct{}

func (promptTestParents) Current() cedarpolicy.Snapshot { return cedarpolicy.Snapshot{} }

type denyPromptDelegate struct{}

func (denyPromptDelegate) DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error) {
	return risk.RiskDecision{Decision: risk.DecisionDeny}, nil
}

func TestPromptGenerationFailurePublishesBarrierAndDelegates(t *testing.T) {
	manager, err := sessionpolicy.NewManager(
		promptTestDeriver{},
		promptpolicy.NewActivationValidator(),
		promptTestParents{},
		func(context.Context) (string, error) { return "token", nil },
		"ins_12345678901234567890123456789012",
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetEnabled(true)
	provider := newPromptPolicyProvider(denyPromptDelegate{}, manager)
	decision, err := provider.DecideHook(t.Context(), risk.HookEvent{
		HookEventName: "UserPromptSubmit",
		Agent:         "codex",
		SessionID:     "session-1",
		Prompt:        "read the report",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != "prompt_policy_generation_failed" || decision.Reason != "Prompt accepted; policy was not generated." {
		t.Fatalf("prompt provider rejected the prompt or lost activation evidence: %+v", decision)
	}
	if snapshot := manager.SnapshotFor(sessionpolicy.SessionKey{Provider: "codex", NativeSessionID: "session-1"}); snapshot.State != sessionpolicy.SessionStateFailed {
		t.Fatalf("generation failure did not publish a failed barrier: %+v", snapshot)
	}

	key := sessionpolicy.SessionKey{Provider: "codex", NativeSessionID: "session-1"}
	if _, err := provider.DecideHook(t.Context(), risk.HookEvent{
		HookEventName: "Stop",
		Agent:         key.Provider,
		SessionID:     key.NativeSessionID,
	}); err != nil {
		t.Fatal(err)
	}
	if snapshot := manager.SnapshotFor(key); snapshot.State != sessionpolicy.SessionStateFailed {
		t.Fatalf("turn-level Stop cleared prompt sequence state: %+v", snapshot)
	}

	if _, err := provider.DecideHook(t.Context(), risk.HookEvent{
		HookEventName: "SessionEnd",
		Agent:         key.Provider,
		SessionID:     key.NativeSessionID,
	}); err != nil {
		t.Fatal(err)
	}
	if snapshot := manager.SnapshotFor(key); snapshot.State != sessionpolicy.SessionStateIdle {
		t.Fatalf("SessionEnd retained prompt sequence state: %+v", snapshot)
	}
}
