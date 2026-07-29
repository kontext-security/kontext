package riskclassifier

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestBreaker(probeErr *error, now *time.Time) *breaker {
	b := newBreaker(func(context.Context) error { return *probeErr })
	b.now = func() time.Time { return *now }
	return b
}

func TestBreakerProbesReadinessBeforeFirstCall(t *testing.T) {
	var probeErr error
	now := time.Now()
	calls := 0
	b := newBreaker(func(context.Context) error { calls++; return probeErr })
	b.now = func() time.Time { return now }

	if !b.allow(context.Background()) {
		t.Fatal("ready endpoint should allow")
	}
	if calls != 1 {
		t.Fatalf("readiness probes = %d, want 1", calls)
	}
	// Subsequent calls must not re-probe; the endpoint is known ready.
	if !b.allow(context.Background()) || calls != 1 {
		t.Fatalf("probe repeated: calls = %d", calls)
	}
}

func TestBreakerTreatsNotReadyAsOff(t *testing.T) {
	probeErr := errors.New("connection refused")
	now := time.Now()
	b := newTestBreaker(&probeErr, &now)

	// A sidecar that is still loading must cost one cheap probe, not a timeout
	// on every command.
	if b.allow(context.Background()) {
		t.Fatal("unready endpoint should not allow")
	}
	for i := 0; i < 5; i++ {
		if b.allow(context.Background()) {
			t.Fatalf("call %d allowed while circuit is open", i)
		}
	}
}

func TestBreakerOpensAfterConsecutiveFailures(t *testing.T) {
	var probeErr error
	now := time.Now()
	b := newTestBreaker(&probeErr, &now)

	if !b.allow(context.Background()) {
		t.Fatal("should start closed")
	}
	for i := 0; i < breakerFailureThreshold; i++ {
		b.fail()
	}
	if b.allow(context.Background()) {
		t.Fatal("circuit should be open after threshold failures")
	}
}

func TestBreakerHalfOpenRecovers(t *testing.T) {
	var probeErr error
	now := time.Now()
	b := newTestBreaker(&probeErr, &now)
	b.allow(context.Background())
	for i := 0; i < breakerFailureThreshold; i++ {
		b.fail()
	}
	if b.allow(context.Background()) {
		t.Fatal("expected open circuit")
	}

	// After the cooldown exactly one probe is admitted.
	now = now.Add(breakerCooldown + time.Second)
	if !b.allow(context.Background()) {
		t.Fatal("cooldown elapsed: one call should be admitted")
	}
	if b.allow(context.Background()) {
		t.Fatal("second concurrent call should be shed while half-open")
	}
	b.succeed()
	if !b.allow(context.Background()) {
		t.Fatal("success should close the circuit")
	}
}

func TestBreakerHalfOpenFailureReopensImmediately(t *testing.T) {
	var probeErr error
	now := time.Now()
	b := newTestBreaker(&probeErr, &now)
	b.allow(context.Background())
	for i := 0; i < breakerFailureThreshold; i++ {
		b.fail()
	}
	now = now.Add(breakerCooldown + time.Second)
	if !b.allow(context.Background()) {
		t.Fatal("expected half-open admission")
	}
	// One bad probe means still unhealthy: reopen without waiting for the
	// threshold again.
	b.fail()
	if b.allow(context.Background()) {
		t.Fatal("failure while half-open should reopen immediately")
	}
}

func TestHTTPReadinessProbe(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("probe path = %q", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ok.Close()
	if err := httpReadinessProbe(ok.Client(), ok.URL+"/v1/models")(context.Background()); err != nil {
		t.Fatalf("ready server: %v", err)
	}

	// llama-server answers 503 while it loads the model.
	loading := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer loading.Close()
	if err := httpReadinessProbe(loading.Client(), loading.URL+"/v1/models")(context.Background()); err == nil {
		t.Fatal("loading server should read as not ready")
	}
}

func TestGuardrailModelsURL(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:18080":                     "http://127.0.0.1:18080/v1/models",
		"http://127.0.0.1:18080/v1":                  "http://127.0.0.1:18080/v1/models",
		"http://127.0.0.1:18080/v1/chat/completions": "http://127.0.0.1:18080/v1/models",
	}
	for in, want := range cases {
		got, err := guardrailModelsURL(in)
		if err != nil {
			t.Fatalf("guardrailModelsURL(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("guardrailModelsURL(%q) = %q, want %q", in, got, want)
		}
	}
}
