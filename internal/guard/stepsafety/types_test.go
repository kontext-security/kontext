package stepsafety

import (
	"context"
	"errors"
	"math"
	"os"
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
	want := 1 / (1 + math.Exp(-(1.3003148180546902*1.0 - 5.527577655786232)))
	if math.Abs(*result.UnsafeProbability-want) > 1e-15 {
		t.Fatalf("unsafe probability = %.17f, want %.17f", *result.UnsafeProbability, want)
	}
	if result.ShadowDecision != DecisionSafe || result.Threshold != Threshold {
		t.Fatalf("result = %+v, want safe below the precision threshold", result)
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

func TestConfigDefaultAndExplicitOptOut(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		enabled     bool
	}{
		{"unset", "", true}, {"empty", "", true}, {"whitespace", "  ", true},
		{"enabled", "1", true}, {"true", "true", true},
		{"disabled", "0", false}, {"false", "false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KONTEXT_STEP_SAFETY_SHADOW", tc.value)
			if tc.name == "unset" {
				if err := os.Unsetenv("KONTEXT_STEP_SAFETY_SHADOW"); err != nil {
					t.Fatal(err)
				}
			}
			for _, key := range []string{"KONTEXT_STEP_SAFETY_TIMEOUT", "KONTEXT_STEP_SAFETY_STARTUP_TIMEOUT", "KONTEXT_STEP_SAFETY_MAX_CONCURRENCY"} {
				t.Setenv(key, "")
				if !tc.enabled {
					// Opt-out must not parse or initialize unused model settings.
					t.Setenv(key, "invalid")
				}
			}
			cfg, err := ConfigFromEnv("/tmp/guard.db")
			if err != nil || cfg.Enabled != tc.enabled {
				t.Fatalf("config=%+v error=%v, want enabled=%v", cfg, err, tc.enabled)
			}
			if !tc.enabled {
				if New(context.Background(), cfg) != nil {
					t.Fatal("opt-out initialized an evaluator")
				}
			} else if cfg.Timeout != defaultTimeout || cfg.MaxConcurrency != 1 || cfg.ModelVersion != ModelVersion {
				t.Fatalf("default advisory configuration changed: %+v", cfg)
			}
		})
	}
}

func TestConfigRejectsInvalidEnableFlag(t *testing.T) {
	t.Setenv("KONTEXT_STEP_SAFETY_SHADOW", "not-a-boolean")
	if _, err := ConfigFromEnv("/tmp/guard.db"); err == nil {
		t.Fatal("invalid enable flag accepted")
	}
}

func TestCandidateThresholdBoundary(t *testing.T) {
	boundary := (math.Log(Threshold/(1-Threshold)) - calibrationBias) / calibrationScale
	for _, tc := range []struct {
		delta    float64
		decision string
	}{{-1e-6, DecisionSafe}, {1e-6, DecisionUnsafe}} {
		backend := &fakeBackend{logits: [2]float64{0, boundary + tc.delta}}
		e := NewWithBackend(backend, time.Second, 1, ModelVersion)
		got := e.Evaluate(context.Background(), Input{ToolName: "clock.sleep"})
		if got.ShadowDecision != tc.decision || got.Enforced {
			t.Fatalf("boundary decision: %+v", got)
		}
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
