package stepsafety

import (
	"context"
	"testing"
)

type countingBackend struct {
	calls int
}

func (b *countingBackend) Infer(context.Context, Input) (InferenceResult, error) {
	b.calls++
	return InferenceResult{}, nil
}

func (b *countingBackend) Health(context.Context) (Health, error) {
	return Health{Status: "ready"}, nil
}

func (b *countingBackend) Close() error { return nil }

func TestStopScoringAnswersWithoutTheModel(t *testing.T) {
	backend := &countingBackend{}
	evaluator := NewWithBackend(backend, 0, 1, "test")
	evaluator.StopScoring()
	got := evaluator.Evaluate(context.Background(), Input{ToolName: "mcp__files__delete_file", UserRequest: "clean up"})
	if got.ErrorCode != ErrorDaemonStopping {
		t.Errorf("error code = %q, want %q", got.ErrorCode, ErrorDaemonStopping)
	}
	if backend.calls != 0 {
		t.Errorf("the model ran %d times", backend.calls)
	}
	var none *Evaluator
	none.StopScoring() // Model off: there's no evaluator.
}
