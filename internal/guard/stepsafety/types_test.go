package stepsafety

import (
	"context"
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBackend struct {
	logits [2]float64
	err    error
	block  <-chan struct{}
	calls  atomic.Int64
}

func (f *fakeBackend) Infer(ctx context.Context, _ Input) (InferenceResult, error) {
	f.calls.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return InferenceResult{}, ctx.Err()
		}
	}
	return InferenceResult{Logits: f.logits}, f.err
}

func (f *fakeBackend) Health(context.Context) (Health, error) {
	return Health{Status: "ready", ModelVersion: ModelVersion, Device: "cpu"}, nil
}

func (f *fakeBackend) Close() error { return nil }

func TestCalibratedProbabilityAndUnsafeThreshold(t *testing.T) {
	backend := &fakeBackend{logits: [2]float64{-0.25, 0.75}}
	evaluator := NewWithBackend(backend, time.Second, 1, "test-model")
	result := evaluator.Evaluate(context.Background(), Input{ToolName: "Bash"})
	if result.UnsafeProbability == nil {
		t.Fatal("unsafe probability missing")
	}
	want := 1 / (1 + math.Exp(-(1.427213430140093*1.0 + 2.953687013257505)))
	if math.Abs(*result.UnsafeProbability-want) > 1e-15 {
		t.Fatalf("unsafe probability = %.17f, want %.17f", *result.UnsafeProbability, want)
	}
	if result.ShadowDecision != DecisionUnsafe || result.Threshold != 0.5 {
		t.Fatalf("result = %+v, want unsafe at threshold 0.5", result)
	}
	if result.ModelVersion != "test-model" || result.Enforced {
		t.Fatalf("result = %+v, want versioned shadow-only output", result)
	}
}

func TestEmptyStructuredHistoryIsNotReportedPresent(t *testing.T) {
	backend := &fakeBackend{logits: [2]float64{1, 0}}
	evaluator := NewWithBackend(backend, time.Second, 1, "test-model")
	result := evaluator.Evaluate(context.Background(), Input{InteractionHistory: "[]"})
	if result.HistoryPresent {
		t.Fatal("empty structured history reported as present")
	}
}

func TestEvaluatorFailsOpenOnTimeout(t *testing.T) {
	backend := &fakeBackend{block: make(chan struct{})}
	evaluator := NewWithBackend(backend, 5*time.Millisecond, 1, ModelVersion)
	result := evaluator.Evaluate(context.Background(), Input{ToolName: "Bash"})
	if result.UnsafeProbability != nil || result.ShadowDecision != DecisionUnavailable {
		t.Fatalf("result = %+v, want unavailable without a score", result)
	}
	if result.ErrorCode != ErrorTimeout || result.Enforced {
		t.Fatalf("result = %+v, want redacted timeout and fail open", result)
	}
}

func TestEvaluatorRedactsBackendErrors(t *testing.T) {
	backend := &fakeBackend{err: errors.New("secret-token-in-backend-error")}
	evaluator := NewWithBackend(backend, time.Second, 1, ModelVersion)
	result := evaluator.Evaluate(context.Background(), Input{})
	if result.ErrorCode != ErrorInference {
		t.Fatalf("error code = %q, want %q", result.ErrorCode, ErrorInference)
	}
}

func TestEvaluatorRejectsOversizedInputBeforeBackend(t *testing.T) {
	backend := &fakeBackend{logits: [2]float64{0, 1}}
	evaluator := NewWithBackend(backend, time.Second, 1, ModelVersion)
	result := evaluator.Evaluate(context.Background(), Input{
		UserRequest: string(make([]byte, maxPretokenizedFieldBytes+1)),
		ToolName:    "Bash",
	})
	if result.ErrorCode != ErrorInputTooLarge || result.UnsafeProbability != nil {
		t.Fatalf("result = %+v, want bounded fail-open result", result)
	}
	if calls := backend.calls.Load(); calls != 0 {
		t.Fatalf("backend calls = %d, want preprocessing rejection before inference", calls)
	}
}

func TestEvaluatorBoundsConcurrency(t *testing.T) {
	release := make(chan struct{})
	backend := &fakeBackend{block: release}
	evaluator := NewWithBackend(backend, time.Second, 1, ModelVersion)
	firstDone := make(chan Evaluation, 1)
	go func() { firstDone <- evaluator.Evaluate(context.Background(), Input{}) }()
	for backend.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	secondCtx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	second := evaluator.Evaluate(secondCtx, Input{})
	if second.ErrorCode != ErrorConcurrency {
		t.Fatalf("second error = %q, want bounded-concurrency timeout", second.ErrorCode)
	}
	close(release)
	<-firstDone
}

func TestConfigDisabledByDefault(t *testing.T) {
	cfg, err := ConfigFromEnv("/tmp/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("step safety enabled without feature flag")
	}
}

func TestConfigRejectsTimeoutBeyondManagedHookReservation(t *testing.T) {
	t.Setenv("KONTEXT_STEP_SAFETY_SHADOW", "true")
	t.Setenv("KONTEXT_STEP_SAFETY_TIMEOUT", "501ms")
	if _, err := ConfigFromEnv("/tmp/guard.db"); err == nil {
		t.Fatal("ConfigFromEnv() error = nil, want timeout bound")
	}
}

func TestExcludedToolsNeverReachInference(t *testing.T) {
	backend := &fakeBackend{}
	evaluator := NewWithBackend(backend, time.Second, 1, ModelVersion)
	for _, name := range []string{"Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch", "functions.apply_patch", "mcp__filesystem__read_file", "filesystem.write_file", "read_text_file", "read_multiple_files"} {
		// Even non-JSON arguments must not be inspected for excluded tools.
		result := evaluator.Evaluate(context.Background(), Input{ToolName: name, ToolArguments: func() {}})
		if result.ErrorCode != ErrorExcludedTool || result.UnsafeProbability != nil || result.Enforced {
			t.Fatalf("%s: %+v", name, result)
		}
	}
	if backend.calls.Load() != 0 {
		t.Fatal("excluded tool reached inference")
	}
	for _, name := range []string{"Bash", "shell", "read_email", "write_message", "search", "get_config"} {
		if ExcludedTool(name) {
			t.Errorf("unrelated tool excluded: %s", name)
		}
	}
}

type nonCancellingBackend struct {
	fakeBackend
	started chan struct{}
	release chan struct{}
}

func (b *nonCancellingBackend) Infer(context.Context, Input) (InferenceResult, error) {
	b.calls.Add(1)
	close(b.started)
	<-b.release
	return InferenceResult{Logits: [2]float64{0, 1}}, nil
}

func TestDeadlineDoesNotWaitForNativeCompletionOrReleaseItsSlot(t *testing.T) {
	backend := &nonCancellingBackend{started: make(chan struct{}), release: make(chan struct{})}
	evaluator := NewWithBackend(backend, 20*time.Millisecond, 1, ModelVersion)
	done := make(chan Evaluation, 1)
	go func() { done <- evaluator.Evaluate(context.Background(), Input{ToolName: "Bash"}) }()
	<-backend.started
	select {
	case result := <-done:
		if result.ErrorCode != ErrorTimeout || result.UnsafeProbability != nil {
			t.Fatalf("timed-out result=%+v", result)
		}
	case <-time.After(time.Second):
		close(backend.release)
		t.Fatal("deadline waited for native completion")
	}
	next := evaluator.Evaluate(context.Background(), Input{ToolName: "Bash"})
	if next.ErrorCode != ErrorConcurrency || backend.calls.Load() != 1 {
		t.Fatalf("outstanding work was not bounded: %+v, calls=%d", next, backend.calls.Load())
	}
	close(backend.release)
}

func TestNonFiniteOutputIsUnavailable(t *testing.T) {
	for _, value := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		evaluator := NewWithBackend(&fakeBackend{logits: [2]float64{0, value}}, time.Second, 1, ModelVersion)
		result := evaluator.Evaluate(context.Background(), Input{ToolName: "Bash"})
		if result.ErrorCode != ErrorInvalidOutput || result.UnsafeProbability != nil {
			t.Fatalf("invalid output was scored: %+v", result)
		}
	}
}
