package stepsafety

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// heldLoader stands in for loading the model: it lasts until the test lets go or
// the load is called off.
type heldLoader struct {
	release chan struct{}
	backend Backend
	err     error
}

func newHeldLoader(backend Backend) *heldLoader {
	return &heldLoader{release: make(chan struct{}), backend: backend}
}

func (l *heldLoader) load(ctx context.Context) (Backend, error) {
	select {
	case <-l.release:
		return l.backend, l.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func loadConfig() Config {
	return Config{Enabled: true, Timeout: time.Second, StartupTimeout: time.Minute, MaxConcurrency: 1, ModelVersion: "test"}
}

var scoredInput = Input{ToolName: "mcp__files__delete_file", UserRequest: "clean up"}

func evaluateAsync(e *Evaluator, ctx context.Context) <-chan Evaluation {
	got := make(chan Evaluation, 1)
	go func() { got <- e.Evaluate(ctx, scoredInput) }()
	return got
}

func awaitEvaluation(t *testing.T, got <-chan Evaluation) Evaluation {
	t.Helper()
	select {
	case result := <-got:
		return result
	case <-time.After(10 * time.Second):
		t.Fatal("the evaluation is still waiting")
		return Evaluation{}
	}
}

func awaitClosed(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("the load didn't end")
	}
}

func TestCallDuringTheLoadIsScoredOnceTheModelIsThere(t *testing.T) {
	const load = 2 * time.Second
	cfg := loadConfig()
	// Shorter than the load, so a clock that started before the load runs out, and
	// long enough for a slow runner to score one call.
	cfg.Timeout = time.Second
	backend := &fakeBackend{logits: [2]float64{0, 5}}
	loader := newHeldLoader(backend)
	e := NewWithLoader(context.Background(), cfg, loader.load)
	defer e.Close()

	got := evaluateAsync(e, context.Background())
	select {
	case result := <-got:
		t.Fatalf("answered before the model was there: %+v", result)
	case <-time.After(load):
	}
	close(loader.release)

	result := awaitEvaluation(t, got)
	if result.ErrorCode != "" || result.ShadowDecision != DecisionUnsafe {
		t.Fatalf("got %+v, want a score", result)
	}
	if backend.calls.Load() != 1 {
		t.Errorf("the model ran %d times", backend.calls.Load())
	}
	// Uploaded with the verdict, and it says how long the model took.
	if result.LatencyMS >= float64(load.Milliseconds()) {
		t.Errorf("latency %.0f ms counts the wait for the load", result.LatencyMS)
	}
}

func TestHealthSaysLoadingUntilTheModelIsThere(t *testing.T) {
	loader := newHeldLoader(&fakeBackend{})
	e := NewWithLoader(context.Background(), loadConfig(), loader.load)
	defer e.Close()

	health := e.Health(context.Background())
	if health.Status != "loading" || !health.Enabled || health.ErrorCode != "" || health.ModelVersion != "test" {
		t.Errorf("during the load: %+v", health)
	}
	close(loader.release)
	awaitClosed(t, e.Loaded())
	if health := e.Health(context.Background()); health.Status != "ready" || !health.Enabled {
		t.Errorf("after the load: %+v", health)
	}
}

func TestStopScoringReleasesACallWaitingForTheLoad(t *testing.T) {
	backend := &fakeBackend{}
	loader := newHeldLoader(backend)
	e := NewWithLoader(context.Background(), loadConfig(), loader.load)
	defer e.Close()

	got := evaluateAsync(e, context.Background())
	e.StopScoring()
	result := awaitEvaluation(t, got)
	if result.ErrorCode != ErrorDaemonStopping {
		t.Errorf("error code = %q, want %q", result.ErrorCode, ErrorDaemonStopping)
	}
	if backend.calls.Load() != 0 {
		t.Errorf("the model ran %d times", backend.calls.Load())
	}
}

// The daemon's context ends first on a stop, and a record shouldn't read as a
// broken model.
func TestStopDuringTheLoadReadsAsStopping(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loader := newHeldLoader(&fakeBackend{})
	e := NewWithLoader(ctx, loadConfig(), loader.load)
	defer e.Close()

	got := evaluateAsync(e, context.Background())
	cancel()
	if result := awaitEvaluation(t, got); result.ErrorCode != ErrorDaemonStopping {
		t.Errorf("error code = %q, want %q", result.ErrorCode, ErrorDaemonStopping)
	}
	awaitClosed(t, e.Loaded())
	if health := e.Health(context.Background()); health.Status != "unavailable" || health.ErrorCode != ErrorDaemonStopping {
		t.Errorf("health = %+v", health)
	}
}

func TestLoadPastTheStartupTimeoutLeavesTheModelUnavailable(t *testing.T) {
	cfg := loadConfig()
	cfg.StartupTimeout = 20 * time.Millisecond
	loader := newHeldLoader(&fakeBackend{})
	e := NewWithLoader(context.Background(), cfg, loader.load)
	defer e.Close()

	got := evaluateAsync(e, context.Background())
	if result := awaitEvaluation(t, got); result.ErrorCode != ErrorTimeout || result.ShadowDecision != DecisionUnavailable {
		t.Errorf("got %+v, want %q", result, ErrorTimeout)
	}
	if health := e.Health(context.Background()); health.Status != "unavailable" || health.ErrorCode != ErrorTimeout {
		t.Errorf("health = %+v", health)
	}
}

func TestFailedLoadLeavesTheModelUnavailable(t *testing.T) {
	loader := newHeldLoader(nil)
	loader.err = backendError(ErrorUnavailable, errors.New("no weights"))
	e := NewWithLoader(context.Background(), loadConfig(), loader.load)
	defer e.Close()

	got := evaluateAsync(e, context.Background())
	close(loader.release)
	if result := awaitEvaluation(t, got); result.ErrorCode != ErrorUnavailable {
		t.Errorf("error code = %q, want %q", result.ErrorCode, ErrorUnavailable)
	}
	if health := e.Health(context.Background()); health.Status != "unavailable" || health.ErrorCode != ErrorUnavailable {
		t.Errorf("health = %+v", health)
	}
	if code := e.LoadError(); code != ErrorUnavailable {
		t.Errorf("load error = %q, want %q", code, ErrorUnavailable)
	}
}

// Nothing passes a hook's context here today, since scoring is deferred. If that
// ever changes, the hook mustn't sit out the load.
func TestCallersDeadlineEndsTheWaitForTheLoad(t *testing.T) {
	loader := newHeldLoader(&fakeBackend{})
	e := NewWithLoader(context.Background(), loadConfig(), loader.load)
	defer e.Close()

	ctx, cancel := context.WithCancel(context.Background())
	got := evaluateAsync(e, ctx)
	cancel()
	if result := awaitEvaluation(t, got); result.ErrorCode != ErrorTimeout {
		t.Errorf("error code = %q, want %q", result.ErrorCode, ErrorTimeout)
	}
}

// Calls that never reach the model have nothing to wait for.
func TestCallsThatSkipTheModelDontWaitForTheLoad(t *testing.T) {
	loader := newHeldLoader(&fakeBackend{})
	e := NewWithLoader(context.Background(), loadConfig(), loader.load)
	defer e.Close()

	got := make(chan Evaluation, 1)
	go func() {
		got <- e.Evaluate(context.Background(), Input{ToolName: "mcp__files__delete_file", RequestTooLarge: true})
	}()
	if result := awaitEvaluation(t, got); result.ErrorCode != ErrorInputTooLarge {
		t.Errorf("error code = %q, want %q", result.ErrorCode, ErrorInputTooLarge)
	}
}

type closeCountingBackend struct {
	fakeBackend
	closes atomic.Int64
}

func (b *closeCountingBackend) Close() error {
	b.closes.Add(1)
	return nil
}

func TestCloseDuringTheLoadEndsItAndReleasesWaiters(t *testing.T) {
	loader := newHeldLoader(&fakeBackend{})
	e := NewWithLoader(context.Background(), loadConfig(), loader.load)

	got := evaluateAsync(e, context.Background())
	closed := make(chan struct{})
	go func() {
		_ = e.Close()
		close(closed)
	}()
	awaitClosed(t, closed)
	if result := awaitEvaluation(t, got); result.ErrorCode != ErrorDaemonStopping {
		t.Errorf("error code = %q, want %q", result.ErrorCode, ErrorDaemonStopping)
	}
}

func TestCloseClosesALoadedBackend(t *testing.T) {
	backend := &closeCountingBackend{}
	loader := newHeldLoader(backend)
	close(loader.release)
	e := NewWithLoader(context.Background(), loadConfig(), loader.load)
	awaitClosed(t, e.Loaded())
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if backend.closes.Load() != 1 {
		t.Errorf("closed %d times", backend.closes.Load())
	}
	// The host's log asks this, and closing mustn't read as a failed load.
	if code := e.LoadError(); code != "" {
		t.Errorf("load error after a clean load and a close: %q", code)
	}
}

// A load that finishes as Close arrives still gets its backend closed.
func TestCloseWaitsForALoadThatStillFinishes(t *testing.T) {
	backend := &closeCountingBackend{}
	finish := make(chan struct{})
	e := NewWithLoader(context.Background(), loadConfig(), func(ctx context.Context) (Backend, error) {
		<-ctx.Done()
		<-finish
		return backend, nil
	})
	closed := make(chan struct{})
	go func() {
		_ = e.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned with the load still running")
	case <-time.After(100 * time.Millisecond):
	}
	close(finish)
	awaitClosed(t, closed)
	if backend.closes.Load() != 1 {
		t.Errorf("closed %d times", backend.closes.Load())
	}
}

func TestBackgroundLoadIsOffWhenTheModelIs(t *testing.T) {
	if e := NewBackground(context.Background(), Config{Enabled: false}); e != nil {
		t.Errorf("got an evaluator: %+v", e)
	}
	var none *Evaluator
	awaitClosed(t, none.Loaded())
}

// Evaluators that were handed their model have no load to wait for.
func TestEvaluatorWithABackendIsLoadedAtOnce(t *testing.T) {
	e := NewWithBackend(&fakeBackend{}, time.Second, 1, "test")
	awaitClosed(t, e.Loaded())
}
