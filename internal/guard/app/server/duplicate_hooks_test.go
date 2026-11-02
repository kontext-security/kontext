package server

import (
	"context"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
)

// countingPolicy allows everything and counts its decisions.
type countingPolicy struct{ calls atomic.Int32 }

func (p *countingPolicy) DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error) {
	p.calls.Add(1)
	return risk.RiskDecision{Decision: risk.DecisionAllow}, nil
}

// Codex hands every hooks file the same event at once, so a double install
// sends the daemon two copies over its socket. With the recorder wedged, and
// with it the advisory model that runs in the record job, both copies and a
// late one are answered from one decision: no copy waits on recording, and the
// ledger keeps one row per event and one turn.
func TestDuplicateHookCopiesShareOneDecision(t *testing.T) {
	for _, merlin := range []bool{false, true} {
		t.Run(fmt.Sprintf("merlin=%v", merlin), func(t *testing.T) {
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
			policy := &countingPolicy{}
			srv, err := NewServerWithPolicyAndOptions(store, policy, Options{StepSafety: evaluator, DeferRecord: recorder.Submit})
			if err != nil {
				t.Fatal(err)
			}
			service, err := localruntime.NewService(localruntime.Options{SocketPath: filepath.Join(hermetic.SocketDir(t), "s.sock"), Core: srv.RuntimeCore()})
			if err != nil {
				t.Fatal(err)
			}
			if err := service.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { release(); service.Stop() })
			client := localruntime.NewClient(service.SocketPath())
			client.Timeout = time.Second
			late := localruntime.NewClient(service.SocketPath())
			late.Timeout = 250 * time.Millisecond

			eventIDs := map[hook.HookName]string{}
			for _, event := range []hook.Event{
				{SessionID: "copies", Agent: "codex", HookName: hook.HookPreToolUse, ToolName: "clock.sleep", ToolUseID: "call_1", ToolInput: map[string]any{"duration_ms": 1}},
				{SessionID: "copies", Agent: "codex", HookName: hook.HookUserPromptSubmit, TranscriptPath: filepath.Join(t.TempDir(), "rollout.jsonl"), ToolInput: map[string]any{"prompt": "fix the build"}},
			} {
				ids := make(chan string, 2)
				for range 2 {
					go func() {
						result, err := client.Process(context.Background(), event)
						if err != nil || result.Decision != hook.DecisionAllow {
							t.Errorf("%s copy = %+v, %v", event.HookName, result, err)
						}
						ids <- result.EventID
					}()
				}
				first, second := <-ids, <-ids
				// The first copy's record still waits for the recorder.
				third, err := late.Process(context.Background(), event)
				if err != nil || first == "" || second != first || third.EventID != first {
					t.Fatalf("%s copies got events %q, %q and %q (%v), want one", event.HookName, first, second, third.EventID, err)
				}
				eventIDs[event.HookName] = first
			}
			if got := policy.calls.Load(); got != 2 {
				t.Fatalf("policy decisions = %d, want 2", got)
			}
			if len(recorder.jobs) != deferredRecordQueueSize {
				t.Fatal("test did not keep the recorder wedged")
			}
			release()
			service.Stop()
			if err := recorder.Drain(context.Background()); err != nil {
				t.Fatal(err)
			}
			decided := eventIDs[hook.HookPreToolUse]
			rows, err := store.Events(context.Background(), "copies")
			if err != nil || len(rows) != 1 || rows[0].ID != decided {
				t.Fatalf("decisions = %+v, %v; want one, %s", rows, err, decided)
			}
			// A prompt's turn is saved with the prompt's own record.
			if turns, err := store.PendingTurns(context.Background(), 10); err != nil || len(turns) != 1 {
				t.Fatalf("turns = %+v, %v; want one", turns, err)
			}
			if merlin {
				verdicts, err := store.StepSafetyVerdictsForSession(context.Background(), "copies")
				if err != nil || len(verdicts) != 1 {
					t.Fatalf("advisory verdicts = %+v, %v; want one", verdicts, err)
				}
			}
		})
	}
}
