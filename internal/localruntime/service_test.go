package localruntime

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/runtimecore"
)

func TestServiceEvaluatesBlockingHook(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{
		evaluateResult: hook.Result{
			Decision: hook.DecisionDeny,
			Reason:   "blocked by runtime",
		},
	}
	service := newTestService(t, runtime, false)
	client := NewClient(service.SocketPath())

	result, err := client.Process(context.Background(), hook.Event{
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny || result.Reason != "blocked by runtime" {
		t.Fatalf("Process() = %+v, want runtime deny result", result)
	}
	if got := runtime.evaluateCalls.Load(); got != 1 {
		t.Fatalf("EvaluateHook calls = %d, want 1", got)
	}
}

// The decision ID must survive the socket protocol: a runtime that answers
// before persisting hands the client the only handle it will ever have to the
// eventual record.
func TestServiceCarriesEventIDOverSocket(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{
		evaluateResult: hook.Result{
			Decision: hook.DecisionAllow,
			EventID:  "act_pre-minted",
		},
	}
	service := newTestService(t, runtime, false)
	client := NewClient(service.SocketPath())

	result, err := client.Process(context.Background(), hook.Event{
		HookName: hook.HookPreToolUse,
		ToolName: "Bash",
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.EventID != "act_pre-minted" {
		t.Fatalf("EventID over the socket = %q, want %q", result.EventID, "act_pre-minted")
	}
}

func TestServiceCanAckTelemetryBeforeAsyncIngest(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{ingested: make(chan hook.Event, 1)}
	service := newTestService(t, runtime, true)
	client := NewClient(service.SocketPath())

	result, err := client.Process(context.Background(), hook.Event{
		SessionID: "agent-session",
		HookName:  hook.HookPostToolUse,
		ToolName:  "Bash",
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("Process().Decision = %q, want allow", result.Decision)
	}

	select {
	case event := <-runtime.ingested:
		if event.HookName != hook.HookPostToolUse {
			t.Fatalf("ingested hook = %q, want PostToolUse", event.HookName)
		}
		if event.SessionID != "agent-session" {
			t.Fatalf("ingested session = %q, want agent-session", event.SessionID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("async ingest did not run")
	}
}

func TestServiceDoesNotAsyncIngestBlockingPromptSubmit(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{
		evaluateResult: hook.Result{
			Decision: hook.DecisionDeny,
			Reason:   "blocked by runtime",
		},
	}
	service := newTestService(t, runtime, true)
	client := NewClient(service.SocketPath())

	result, err := client.Process(context.Background(), hook.Event{
		SessionID: "agent-session",
		HookName:  hook.HookUserPromptSubmit,
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny || result.Reason != "blocked by runtime" {
		t.Fatalf("Process() = %+v, want runtime deny result", result)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if got := runtime.evaluateCalls.Load(); got != 1 {
		t.Fatalf("EvaluateHook calls = %d, want 1", got)
	}
	if got := runtime.ingestCalls.Load(); got != 0 {
		t.Fatalf("IngestEvent calls = %d, want 0", got)
	}
}

func TestServiceShutdownDrainsAsyncIngest(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{
		ingestStarted: make(chan struct{}),
		releaseIngest: make(chan struct{}),
	}
	service := newTestService(t, runtime, true)
	client := NewClient(service.SocketPath())

	result, err := client.Process(context.Background(), hook.Event{
		SessionID: "agent-session",
		HookName:  hook.HookPostToolUse,
		ToolName:  "Bash",
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("Process().Decision = %q, want allow", result.Decision)
	}

	select {
	case <-runtime.ingestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("async ingest did not start")
	}

	done := make(chan error, 1)
	go func() {
		done <- service.Shutdown(context.Background())
	}()
	select {
	case err := <-done:
		t.Fatalf("Shutdown() returned before async ingest drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(runtime.releaseIngest)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown() did not return after async ingest completed")
	}
}

func TestServiceShutdownDrainsAfterSocketRemoveError(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{
		ingestStarted: make(chan struct{}),
		releaseIngest: make(chan struct{}),
	}
	service := newTestService(t, runtime, true)
	client := NewClient(service.SocketPath())

	result, err := client.Process(context.Background(), hook.Event{
		SessionID: "agent-session",
		HookName:  hook.HookPostToolUse,
		ToolName:  "Bash",
	})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("Process().Decision = %q, want allow", result.Decision)
	}
	select {
	case <-runtime.ingestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("async ingest did not start")
	}

	nonEmptyDir := filepath.Join(t.TempDir(), "remove-error")
	if err := os.Mkdir(nonEmptyDir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(nonEmptyDir, "child"), []byte("busy"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	service.socketPath = nonEmptyDir

	done := make(chan error, 1)
	go func() {
		done <- service.Shutdown(context.Background())
	}()
	select {
	case err := <-done:
		t.Fatalf("Shutdown() returned before async ingest drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(runtime.releaseIngest)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Shutdown() error = nil, want socket remove error")
		}
		if !strings.Contains(err.Error(), "remove local runtime socket") {
			t.Fatalf("Shutdown() error = %v, want socket remove error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown() did not return after async ingest completed")
	}
}

func TestServiceUsesCustomFailureResult(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{evaluateErr: context.DeadlineExceeded}
	core, err := runtimecore.New(runtime)
	if err != nil {
		t.Fatalf("runtimecore.New() error = %v", err)
	}
	result := newTestServiceWithOptions(t, Options{
		Core: core,
		OnFailure: func(event hook.Event, err error) hook.Result {
			if event.HookName != hook.HookPreToolUse || err == nil {
				t.Fatalf("failure callback event=%+v err=%v", event, err)
			}
			return hook.Result{
				Decision: hook.DecisionAllow,
				Reason:   "custom fail-open",
			}
		},
	})
	client := NewClient(result.SocketPath())

	got, err := client.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse})
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if got.Decision != hook.DecisionAllow || got.Reason != "custom fail-open" {
		t.Fatalf("Process() = %+v, want custom fail-open result", got)
	}
}

func TestServiceFailsClosedWhenBlockingHookPayloadCannotDecode(t *testing.T) {
	t.Parallel()

	service := newTestService(t, &stubRuntime{}, false)
	result := service.process(context.Background(), &EvaluateRequest{
		HookEvent: "PreToolUse",
		ToolInput: []byte(`{`),
	})

	if result.Allowed {
		t.Fatal("result.Allowed = true, want false")
	}
	if result.Decision != string(hook.DecisionDeny) {
		t.Fatalf("result.Decision = %q, want deny", result.Decision)
	}
}

func TestServiceAllowsNonblockingHookPayloadDecodeFailure(t *testing.T) {
	t.Parallel()

	service := newTestService(t, &stubRuntime{}, true)
	result := service.process(context.Background(), &EvaluateRequest{
		HookEvent: "PostToolUse",
		ToolInput: []byte(`{`),
	})

	if !result.Allowed {
		t.Fatal("result.Allowed = false, want true")
	}
	if result.Decision != string(hook.DecisionAllow) {
		t.Fatalf("result.Decision = %q, want allow", result.Decision)
	}
}

func newTestService(t *testing.T, runtime *stubRuntime, asyncIngest bool) *Service {
	t.Helper()

	core, err := runtimecore.New(runtime)
	if err != nil {
		t.Fatalf("runtimecore.New() error = %v", err)
	}
	return newTestServiceWithOptions(t, Options{
		Core:        core,
		AgentName:   "claude",
		AsyncIngest: asyncIngest,
		Diagnostic:  diagnostic.New(io.Discard, false),
	})
}

func newTestServiceWithOptions(t *testing.T, opts Options) *Service {
	t.Helper()

	dir, err := os.MkdirTemp("/tmp", "kontext-runtime-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	opts.SocketPath = filepath.Join(dir, "kontext.sock")
	if opts.AgentName == "" {
		opts.AgentName = "claude"
	}
	if !opts.Diagnostic.Enabled() {
		opts.Diagnostic = diagnostic.New(io.Discard, false)
	}
	service, err := NewService(Options{
		SocketPath:  opts.SocketPath,
		Core:        opts.Core,
		SessionID:   opts.SessionID,
		AgentName:   opts.AgentName,
		AsyncIngest: opts.AsyncIngest,
		OnFailure:   opts.OnFailure,
		Diagnostic:  opts.Diagnostic,
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(service.Stop)
	return service
}

type stubRuntime struct {
	evaluateResult hook.Result
	evaluateErr    error
	ingested       chan hook.Event
	ingestStarted  chan struct{}
	releaseIngest  chan struct{}
	evaluateCalls  atomic.Int32
	ingestCalls    atomic.Int32
	startedIngest  atomic.Bool
}

func (s *stubRuntime) EvaluateHook(_ context.Context, _ hook.Event) (hook.Result, error) {
	s.evaluateCalls.Add(1)
	return s.evaluateResult, s.evaluateErr
}

func (s *stubRuntime) IngestEvent(ctx context.Context, event hook.Event) (hook.Result, error) {
	s.ingestCalls.Add(1)
	if s.ingestStarted != nil && s.startedIngest.CompareAndSwap(false, true) {
		close(s.ingestStarted)
	}
	if s.releaseIngest != nil {
		select {
		case <-s.releaseIngest:
		case <-ctx.Done():
			return hook.Result{}, ctx.Err()
		}
	}
	if s.ingested != nil {
		s.ingested <- event
	}
	return hook.Result{Decision: hook.DecisionAllow}, nil
}
