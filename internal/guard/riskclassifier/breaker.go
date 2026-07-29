package riskclassifier

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"
)

const (
	// breakerFailureThreshold consecutive failures open the circuit. Low on
	// purpose: the classifier is advisory, so shedding it early costs nothing,
	// while retrying a sick sidecar costs every tool call the full timeout.
	breakerFailureThreshold = 3

	// breakerCooldown is how long the circuit stays open before one probe is
	// allowed through. Long enough that a llama-server still loading its model
	// finishes in the meantime, short enough that a transient blip does not
	// disable the LLM for a whole session.
	breakerCooldown = 30 * time.Second

	// readinessTimeout bounds the /v1/models probe. Readiness is checked before
	// any classify call, so a sidecar that is still loading costs one cheap
	// request rather than a timeout on every command.
	readinessTimeout = 500 * time.Millisecond
)

// ErrLLMUnavailable is recorded as llm_error when the circuit is open or the
// endpoint is not ready. It is a skip, not a failure of the model.
var ErrLLMUnavailable = errors.New("guardrail unavailable: endpoint not ready")

// breakerState is the classic three-state circuit.
type breakerState int

const (
	breakerClosed breakerState = iota
	breakerOpen
	breakerHalfOpen
)

// breaker sheds guardrail calls when the sidecar is unhealthy, and probes
// readiness before letting the first call through.
//
// Both mechanisms exist for the same reason: the guardrail's timeout is sized
// for warm inference (tens of ms), but a llama-server that is loading a model
// takes seconds. Without these, every command during startup would pay the full
// timeout and fail anyway. With them, an unready sidecar costs one probe and is
// then treated as off until it recovers.
type breaker struct {
	mu           sync.Mutex
	state        breakerState
	failures     int
	openedAt     time.Time
	readyChecked bool
	ready        bool

	// now and probe are injectable for tests.
	now   func() time.Time
	probe func(context.Context) error
}

func newBreaker(probe func(context.Context) error) *breaker {
	return &breaker{now: time.Now, probe: probe}
}

// allow reports whether a classify call may proceed. It performs the readiness
// probe on first use and after the circuit reopens, so callers never issue a
// classify request against an endpoint that has not answered.
func (b *breaker) allow(ctx context.Context) bool {
	b.mu.Lock()
	switch b.state {
	case breakerOpen:
		if b.now().Sub(b.openedAt) < breakerCooldown {
			b.mu.Unlock()
			return false
		}
		// Cooldown elapsed: let exactly one call through to test the water.
		b.state = breakerHalfOpen
		b.readyChecked = false
	case breakerHalfOpen:
		// A probe is already in flight; shed the rest rather than stampeding a
		// sidecar that may still be loading.
		b.mu.Unlock()
		return false
	}
	needsReadiness := !b.readyChecked
	b.mu.Unlock()

	if !needsReadiness {
		return true
	}
	err := b.runProbe(ctx)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.readyChecked = true
	b.ready = err == nil
	if err != nil {
		b.tripLocked()
		return false
	}
	return true
}

func (b *breaker) runProbe(ctx context.Context) error {
	if b.probe == nil {
		return nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, readinessTimeout)
	defer cancel()
	return b.probe(probeCtx)
}

// succeed closes the circuit.
func (b *breaker) succeed() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.state = breakerClosed
	b.failures = 0
}

// fail counts a failure and opens the circuit once the threshold is reached. A
// failure while half-open reopens immediately — one bad probe means the sidecar
// is still not healthy.
func (b *breaker) fail() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state == breakerHalfOpen {
		b.tripLocked()
		return
	}
	b.failures++
	if b.failures >= breakerFailureThreshold {
		b.tripLocked()
	}
}

func (b *breaker) tripLocked() {
	b.state = breakerOpen
	b.failures = 0
	b.openedAt = b.now()
	// Re-probe readiness when the cooldown lets a call through.
	b.readyChecked = false
}

// httpReadinessProbe reports whether an OpenAI-compatible endpoint is serving.
// llama-server answers /v1/models only once the model is loaded, which is
// exactly the signal needed: "reachable but still loading" reads as not ready.
func httpReadinessProbe(client *http.Client, modelsURL string) func(context.Context) error {
	return func(ctx context.Context) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return errors.New("guardrail endpoint returned " + resp.Status)
		}
		return nil
	}
}
