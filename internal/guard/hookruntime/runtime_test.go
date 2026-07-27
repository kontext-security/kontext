package hookruntime

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/hook"
)

func TestRunObserveModeAllowsUnavailableBlockingHook(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: hook.Event{HookName: hook.HookPreToolUse},
	}
	err := Run(context.Background(), adapter, stubProcessor{err: errors.New("offline")}, ModeObserve, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %s, want allow", adapter.result.Decision)
	}
	if adapter.result.Reason != "Kontext observe mode: would allow; telemetry allowed" {
		t.Fatalf("reason = %q", adapter.result.Reason)
	}
}

func TestRunEnforceModeDeniesUnavailableBlockingHook(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: hook.Event{HookName: hook.HookPreToolUse},
	}
	err := Run(context.Background(), adapter, stubProcessor{err: errors.New("offline")}, ModeEnforce, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %s, want deny", adapter.result.Decision)
	}
	if adapter.result.Reason != "Kontext daemon unavailable" {
		t.Fatalf("reason = %q", adapter.result.Reason)
	}
}

func TestRunNonBlockingHookCannotBlock(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: hook.Event{HookName: hook.HookPostToolUse},
	}
	err := Run(context.Background(), adapter, stubProcessor{result: hook.Result{Decision: hook.DecisionDeny, Reason: "blocked"}}, ModeEnforce, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %s, want allow", adapter.result.Decision)
	}
}

func TestRunUserPromptSubmitCanBlock(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: hook.Event{HookName: hook.HookUserPromptSubmit},
	}
	err := Run(context.Background(), adapter, stubProcessor{result: hook.Result{Decision: hook.DecisionDeny, Reason: "blocked"}}, ModeEnforce, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %s, want deny", adapter.result.Decision)
	}
}

func TestRunObserveModeFormatsNonBlockingHookReason(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: hook.Event{HookName: hook.HookPostToolUse},
	}
	err := Run(context.Background(), adapter, stubProcessor{result: hook.Result{Decision: hook.DecisionAllow, Reason: "async telemetry event recorded"}}, ModeObserve, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %s, want allow", adapter.result.Decision)
	}
	if adapter.result.Reason != "Kontext observe mode: would allow; async telemetry event recorded" {
		t.Fatalf("reason = %q", adapter.result.Reason)
	}
}

func TestRunObserveModeAllowsWithWouldDenyReason(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: hook.Event{HookName: hook.HookPreToolUse},
	}
	err := Run(context.Background(), adapter, stubProcessor{result: hook.Result{Decision: hook.DecisionDeny, Reason: "blocked"}}, ModeObserve, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %s, want allow", adapter.result.Decision)
	}
	if adapter.result.Reason != "Kontext observe mode: would deny; blocked" {
		t.Fatalf("reason = %q", adapter.result.Reason)
	}
}

func TestRunUnknownDecisionFailsClosedForBlockingHook(t *testing.T) {
	t.Parallel()

	adapter := &stubAdapter{
		event: hook.Event{HookName: hook.HookPreToolUse},
	}
	err := Run(context.Background(), adapter, stubProcessor{result: hook.Result{Decision: "unexpected"}}, ModeEnforce, bytes.NewReader(nil), io.Discard, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.result.Decision != hook.DecisionDeny {
		t.Fatalf("decision = %s, want deny", adapter.result.Decision)
	}
}

type stubProcessor struct {
	result hook.Result
	err    error
}

func (p stubProcessor) Process(context.Context, hook.Event) (hook.Result, error) {
	return p.result, p.err
}

type stubAdapter struct {
	event     hook.Event
	decodeErr error
	result    hook.Result
}

func (a *stubAdapter) Decode(io.Reader) (hook.Event, error) {
	return a.event, a.decodeErr
}

func (a *stubAdapter) Encode(_ io.Writer, _ hook.Event, result hook.Result) error {
	a.result = result
	return nil
}

func (a *stubAdapter) MalformedHookName() hook.HookName {
	return hook.HookPreToolUse
}

func TestParseModeRemote(t *testing.T) {
	mode, err := ParseMode(" Remote ")
	if err != nil {
		t.Fatalf("ParseMode() error = %v", err)
	}
	if mode != ModeRemote {
		t.Fatalf("mode = %q, want remote", mode)
	}
}

func TestEffectiveResultRemotePassesThroughEnforceStamp(t *testing.T) {
	event := hook.Event{HookName: hook.HookPreToolUse}
	result := effectiveResult(event, hook.Result{Decision: hook.DecisionDeny, Mode: string(ModeEnforce), Reason: "policy deny"}, ModeRemote)
	if result.Decision != hook.DecisionDeny || result.Mode != string(ModeEnforce) {
		t.Fatalf("result = %+v, want authoritative deny passed through", result)
	}
}

func TestEffectiveResultRemoteDowngradesUnstampedToObserve(t *testing.T) {
	event := hook.Event{HookName: hook.HookPreToolUse}
	result := effectiveResult(event, hook.Result{Decision: hook.DecisionDeny, Reason: "would deny"}, ModeRemote)
	if result.Decision != hook.DecisionAllow || result.Mode != string(ModeObserve) {
		t.Fatalf("result = %+v, want observe downgrade", result)
	}
	if result.Reason != "Kontext observe mode: would deny; would deny" {
		t.Fatalf("reason = %q, want observe would-note", result.Reason)
	}
}
