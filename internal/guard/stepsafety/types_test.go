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

func (f *fakeBackend) Infer(ctx context.Context, _ Input) ([2]float64, error) {
	f.calls.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return [2]float64{}, ctx.Err()
		}
	}
	return f.logits, f.err
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
	want := 1 / (1 + math.Exp(-(1.157280529495871*1.0 + 1.1360845295110542)))
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

func TestEvaluatorFailsOpenOnTimeout(t *testing.T) {
	backend := &fakeBackend{block: make(chan struct{})}
	evaluator := NewWithBackend(backend, 5*time.Millisecond, 1, ModelVersion)
	result := evaluator.Evaluate(context.Background(), Input{ToolName: "Write"})
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
