package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
)

func TestHookHTTPOverloadRejectsBeforePolicyEvaluation(t *testing.T) {
	store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := &recordingPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}
	srv, err := NewServerWithPolicyAndOptions(store, policy, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for range cap(srv.hookSlots) {
		srv.hookSlots <- struct{}{}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/hooks/process", strings.NewReader(`{"hook_event_name":"PreToolUse"}`))
	response := httptest.NewRecorder()
	srv.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusServiceUnavailable || policy.called {
		t.Fatalf("overload must precede evaluation: status=%d policy_called=%v", response.Code, policy.called)
	}
}

func TestClosedRecorderRejectsDirectDecisionWithoutReturningEventID(t *testing.T) {
	store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	recorder := NewDeferredRecorder(diagnostic.New(io.Discard, true))
	if err := recorder.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServerWithOptions(store, Options{DeferRecord: recorder.Submit})
	if err != nil {
		t.Fatal(err)
	}
	result, err := srv.ProcessHookEvent(context.Background(), risk.HookEvent{SessionID: "closed", HookEventName: "PreToolUse", ToolName: "clock.sleep"})
	if !errors.Is(err, errRecorderClosed) || result.EventID != "" {
		t.Fatalf("closed recorder must not return an orphan ID: %+v %v", result, err)
	}
}

func saturatedRecorder(t *testing.T) (*DeferredRecorder, func()) {
	t.Helper()
	r := NewDeferredRecorder(diagnostic.New(io.Discard, true))
	blocked := make(chan struct{})
	started := make(chan struct{}, deferredRecordWorkers)
	var once sync.Once
	release := func() { once.Do(func() { close(blocked) }) }
	t.Cleanup(func() { release(); _ = r.Drain(context.Background()) })
	for range deferredRecordWorkers {
		if err := r.Submit(func(context.Context) error {
			started <- struct{}{}
			<-blocked
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for range deferredRecordWorkers {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("recorder workers did not start")
		}
	}
	for range deferredRecordQueueSize {
		if err := r.Submit(func(context.Context) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	return r, release
}

func TestSaturatedRecorderPreservesSettledDecisions(t *testing.T) {
	for _, transport := range []string{"socket", "http"} {
		for _, merlin := range []bool{false, true} {
			for _, decision := range []risk.Decision{risk.DecisionAllow, risk.DecisionDeny} {
				t.Run(fmt.Sprintf("%s/merlin=%v/%s", transport, merlin, decision), func(t *testing.T) {
					store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = store.Close() })
					var evaluator *stepsafety.Evaluator
					if merlin {
						evaluator = stepsafety.NewWithBackend(&capturingStepSafetyBackend{}, time.Second, 1, stepsafety.ModelVersion)
						t.Cleanup(func() { _ = evaluator.Close() })
					}
					recorder, release := saturatedRecorder(t)
					policy := &recordingPolicy{decision: risk.RiskDecision{Decision: decision}}
					if decision == risk.DecisionDeny {
						policy.decision.Cedar = enforcedDenyEvidence()
					}
					srv, err := NewServerWithPolicyAndOptions(store, policy, Options{StepSafety: evaluator, DeferRecord: recorder.Submit})
					if err != nil {
						t.Fatal(err)
					}
					var send func(int) (string, error)
					var stop func()
					if transport == "socket" {
						dir, err := os.MkdirTemp("/tmp", "audit-full-*")
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { _ = os.RemoveAll(dir) })
						service, err := localruntime.NewService(localruntime.Options{SocketPath: filepath.Join(dir, "s.sock"), Core: srv.RuntimeCore()})
						if err != nil {
							t.Fatal(err)
						}
						if err := service.Start(context.Background()); err != nil {
							t.Fatal(err)
						}
						stop = service.Stop
						client := localruntime.NewClient(service.SocketPath())
						client.Timeout = time.Second
						send = func(i int) (string, error) {
							result, err := client.Process(context.Background(), hook.Event{
								SessionID: "saturated", HookName: hook.HookPreToolUse, ToolName: "clock.sleep", ToolUseID: fmt.Sprint(i), ToolInput: map[string]any{"duration_ms": 1},
							})
							if string(result.Decision) != string(decision) {
								return "", fmt.Errorf("decision changed: %+v", result)
							}
							return result.EventID, err
						}
					} else {
						httpServer := httptest.NewServer(srv.Handler())
						stop = httpServer.Close
						client := &http.Client{Timeout: time.Second}
						send = func(i int) (string, error) {
							body, _ := json.Marshal(risk.HookEvent{SessionID: "saturated", HookEventName: "PreToolUse", ToolName: "clock.sleep", ToolUseID: fmt.Sprint(i), ToolInput: map[string]any{"duration_ms": 1}})
							response, err := client.Post(httpServer.URL+"/api/hooks/process", "application/json", bytes.NewReader(body))
							if err != nil {
								return "", err
							}
							defer response.Body.Close()
							// Read to EOF: flushing an unterminated chunked response is
							// insufficient if the handler is still waiting on admission.
							data, err := io.ReadAll(response.Body)
							if err != nil {
								return "", err
							}
							var result ProcessResponse
							if err := json.Unmarshal(data, &result); err != nil {
								return "", err
							}
							if result.Decision != decision {
								return "", fmt.Errorf("decision changed: %+v", result)
							}
							return result.EventID, nil
						}
					}
					t.Cleanup(func() { release(); stop() })
					ids := map[string]bool{}
					for i := range 16 {
						id, err := send(i)
						if err != nil || id == "" || ids[id] {
							t.Fatalf("response id=%q err=%v", id, err)
						}
						ids[id] = true
					}
					if len(recorder.jobs) != deferredRecordQueueSize {
						t.Fatal("test did not retain full queue")
					}
					release()
					stop() // Drain transport submissions before closing recorder admission.
					if err := recorder.Drain(context.Background()); err != nil {
						t.Fatal(err)
					}
					rows, err := store.Events(context.Background(), "saturated")
					if err != nil || len(rows) != len(ids) {
						t.Fatalf("persisted %d/%d rows: %v", len(rows), len(ids), err)
					}
					for _, row := range rows {
						if !ids[row.ID] || row.Decision != decision {
							t.Fatalf("unexpected row: %+v", row)
						}
						delete(ids, row.ID)
						if merlin {
							verdict, err := store.StepSafetyVerdictForAction(context.Background(), row.ID)
							if err != nil || verdict.ShadowDecision != stepsafety.DecisionUnsafe || verdict.Enforced {
								t.Fatalf("missing advisory record: %+v %v", verdict, err)
							}
						}
					}
					if len(ids) != 0 {
						t.Fatalf("orphaned response IDs: %v", ids)
					}
				})
			}
		}
	}
}
