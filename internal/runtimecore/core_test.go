package runtimecore

import (
	"context"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

func TestEvaluateHookRejectsTelemetryHooks(t *testing.T) {
	core, err := New(&recordingRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.EvaluateHook(context.Background(), hook.Event{HookName: hook.HookPostToolUse})
	if err == nil {
		t.Fatal("EvaluateHook() error = nil, want non-blocking hook rejection")
	}
}

func TestIngestEventRejectsBlockingHooks(t *testing.T) {
	core, err := New(&recordingRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = core.IngestEvent(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if err == nil {
		t.Fatal("IngestEvent() error = nil, want blocking hook rejection")
	}
	_, err = core.IngestEvent(context.Background(), hook.Event{HookName: hook.HookUserPromptSubmit})
	if err == nil {
		t.Fatal("IngestEvent(UserPromptSubmit) error = nil, want blocking hook rejection")
	}
}

func TestIngestObservedEventDoesNotApplyOrderedObservationTwice(t *testing.T) {
	runtime := &recordingRuntime{}
	core, err := New(runtime)
	if err != nil {
		t.Fatal(err)
	}
	event := hook.Event{HookName: hook.HookPostToolUse, ToolName: "Read"}
	if err := core.ObserveAsyncEvent(event); err != nil {
		t.Fatal(err)
	}
	if _, err := core.IngestObservedEvent(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if runtime.observeCalls != 1 || runtime.ingestCalls != 1 {
		t.Fatalf("calls observe=%d ingest=%d, want 1/1", runtime.observeCalls, runtime.ingestCalls)
	}
	if _, err := core.IngestEvent(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if runtime.observeCalls != 2 || runtime.ingestCalls != 2 {
		t.Fatalf("direct calls observe=%d ingest=%d, want 2/2", runtime.observeCalls, runtime.ingestCalls)
	}
}

func TestProcessHookRoutesByBlockingCapability(t *testing.T) {
	runtime := &recordingRuntime{
		evaluateResult: hook.Result{Decision: hook.DecisionDeny, Reason: "review"},
		ingestResult:   hook.Result{Decision: hook.DecisionAllow, Reason: "recorded"},
	}
	core, err := New(runtime)
	if err != nil {
		t.Fatal(err)
	}
	evaluate, err := core.ProcessHook(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := core.ProcessHook(context.Background(), hook.Event{HookName: hook.HookUserPromptSubmit})
	if err != nil {
		t.Fatal(err)
	}
	ingest, err := core.ProcessHook(context.Background(), hook.Event{HookName: hook.HookPostToolUse})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.evaluateCalls != 2 || runtime.ingestCalls != 1 {
		t.Fatalf("calls evaluate=%d ingest=%d", runtime.evaluateCalls, runtime.ingestCalls)
	}
	if evaluate.Decision != hook.DecisionDeny || prompt.Decision != hook.DecisionDeny || ingest.Reason != "recorded" {
		t.Fatalf("evaluate=%+v prompt=%+v ingest=%+v", evaluate, prompt, ingest)
	}
}

func TestProcessHookRejectsUnknownHookNames(t *testing.T) {
	runtime := &recordingRuntime{}
	core, err := New(runtime)
	if err != nil {
		t.Fatal(err)
	}

	_, err = core.ProcessHook(context.Background(), hook.Event{HookName: hook.HookName("pretooluse")})
	if err == nil {
		t.Fatal("ProcessHook() error = nil, want unknown hook rejection")
	}
	if runtime.evaluateCalls != 0 || runtime.ingestCalls != 0 {
		t.Fatalf("calls evaluate=%d ingest=%d, want no runtime calls", runtime.evaluateCalls, runtime.ingestCalls)
	}
}

func TestProcessHookEnsuresSessionBeforeEvaluation(t *testing.T) {
	runtime := &recordingSessionRuntime{
		recordingRuntime: recordingRuntime{
			evaluateResult: hook.Result{Decision: hook.DecisionAllow, Reason: "ok"},
		},
	}
	core, err := New(runtime)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := core.ProcessHook(context.Background(), hook.Event{
		HookName: hook.HookPreToolUse,
		Agent:    "claude",
	}); err != nil {
		t.Fatal(err)
	}

	if runtime.ensureCalls != 1 {
		t.Fatalf("EnsureSessionForEvent calls = %d, want 1", runtime.ensureCalls)
	}
	if runtime.lastEvaluateEvent.SessionID != "resolved-session" {
		t.Fatalf("evaluated session = %q, want resolved-session", runtime.lastEvaluateEvent.SessionID)
	}
}

func TestOpenAndCloseSessionDelegateToRuntime(t *testing.T) {
	runtime := &recordingSessionRuntime{}
	core, err := New(runtime)
	if err != nil {
		t.Fatal(err)
	}

	session, err := core.OpenSession(context.Background(), Session{
		ID:     "session-123",
		Agent:  "claude",
		Source: SessionSourceWrapperOwned,
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.ID != "session-123" || runtime.openCalls != 1 {
		t.Fatalf("OpenSession() = %+v calls=%d", session, runtime.openCalls)
	}
	if err := core.CloseSession(context.Background(), "session-123"); err != nil {
		t.Fatal(err)
	}
	if runtime.closeCalls != 1 || runtime.closedSessionID != "session-123" {
		t.Fatalf("CloseSession calls=%d session=%q", runtime.closeCalls, runtime.closedSessionID)
	}
}

func TestNewRejectsMissingRuntime(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("New(nil) error = nil, want error")
	}
}

type recordingRuntime struct {
	evaluateCalls     int
	ingestCalls       int
	observeCalls      int
	evaluateResult    hook.Result
	ingestResult      hook.Result
	err               error
	lastEvaluateEvent hook.Event
}

func (r *recordingRuntime) ObserveAsyncEvent(hook.Event) {
	r.observeCalls++
}

func (r *recordingRuntime) EvaluateHook(_ context.Context, event hook.Event) (hook.Result, error) {
	r.evaluateCalls++
	r.lastEvaluateEvent = event
	if r.err != nil {
		return hook.Result{}, r.err
	}
	if r.evaluateResult.Decision == "" {
		return hook.Result{Decision: hook.DecisionAllow}, nil
	}
	return r.evaluateResult, nil
}

func (r *recordingRuntime) IngestEvent(context.Context, hook.Event) (hook.Result, error) {
	r.ingestCalls++
	if r.err != nil {
		return hook.Result{}, r.err
	}
	if r.ingestResult.Decision == "" {
		return hook.Result{Decision: hook.DecisionAllow}, nil
	}
	return r.ingestResult, nil
}

var _ HookRuntime = (*recordingRuntime)(nil)

type recordingSessionRuntime struct {
	recordingRuntime
	openCalls       int
	closeCalls      int
	ensureCalls     int
	closedSessionID string
}

func (r *recordingSessionRuntime) OpenSession(_ context.Context, session Session) (Session, error) {
	r.openCalls++
	return session, nil
}

func (r *recordingSessionRuntime) CloseSession(_ context.Context, sessionID string) error {
	r.closeCalls++
	r.closedSessionID = sessionID
	return nil
}

func (r *recordingSessionRuntime) EnsureSessionForEvent(_ context.Context, event hook.Event) (hook.Event, error) {
	r.ensureCalls++
	event.SessionID = "resolved-session"
	return event, nil
}

var _ SessionRuntime = (*recordingSessionRuntime)(nil)
