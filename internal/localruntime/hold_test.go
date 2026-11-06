package localruntime

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/policyhold"
	"github.com/kontext-security/kontext/internal/runtimecore"
)

func newHoldService(t *testing.T, runtime *stubRuntime, holdFor func(hook.Event) time.Duration) *Service {
	t.Helper()
	core, err := runtimecore.New(runtime)
	if err != nil {
		t.Fatalf("runtimecore.New() error = %v", err)
	}
	return newTestServiceWithOptions(t, Options{Core: core, HoldFor: holdFor})
}

func preToolUse(id string) hook.Event {
	return hook.Event{HookName: hook.HookPreToolUse, ToolName: "Bash", ToolUseID: id, ToolInput: map[string]any{"command": "true"}}
}

// A held call outlives the hook's normal budget: the deadline moves to the
// end of the hold plus that budget, and the decision sees the hold's end.
func TestHoldableClientWaitsThroughAHold(t *testing.T) {
	t.Parallel()

	var sawDeadline bool
	runtime := &stubRuntime{}
	runtime.evaluateCtx = func(ctx context.Context) (hook.Result, error) {
		_, sawDeadline = policyhold.Deadline(ctx)
		time.Sleep(250 * time.Millisecond)
		return hook.Result{Decision: hook.DecisionDeny, Reason: "policy"}, nil
	}
	service := newHoldService(t, runtime, func(hook.Event) time.Duration { return 400 * time.Millisecond })
	client := NewClient(service.SocketPath())
	client.Timeout = 100 * time.Millisecond

	result, held, err := client.ProcessHoldable(context.Background(), preToolUse("toolu_held"), time.Second)
	if err != nil {
		t.Fatalf("ProcessHoldable() error = %v", err)
	}
	if !held || !sawDeadline {
		t.Fatalf("held = %v, decision saw a hold deadline = %v, want both", held, sawDeadline)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("Decision = %q, want deny", result.Decision)
	}
}

// A hook that predates the capability is never sent a hold frame and its
// decision never waits, even when the daemon would hold.
func TestServiceHoldsNothingWithoutTheCapability(t *testing.T) {
	t.Parallel()

	var sawDeadline bool
	runtime := &stubRuntime{}
	runtime.evaluateCtx = func(ctx context.Context) (hook.Result, error) {
		_, sawDeadline = policyhold.Deadline(ctx)
		return hook.Result{Decision: hook.DecisionDeny, Reason: "policy"}, nil
	}
	service := newHoldService(t, runtime, func(hook.Event) time.Duration { return time.Second })

	result, err := NewClient(service.SocketPath()).Process(context.Background(), preToolUse("toolu_old_hook"))
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if result.Decision != hook.DecisionDeny || sawDeadline {
		t.Fatalf("Decision = %q, decision saw a hold deadline = %v; want the plain answer and no hold", result.Decision, sawDeadline)
	}
}

func TestServiceHoldsOnlyPreToolUseAndOnlyWhenAsked(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		event hook.Event
		hold  time.Duration
	}{
		{"prompt submit", hook.Event{HookName: hook.HookUserPromptSubmit}, time.Second},
		{"no hold wanted", preToolUse("toolu_enrolled"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runtime := &stubRuntime{evaluateResult: hook.Result{Decision: hook.DecisionAllow}}
			service := newHoldService(t, runtime, func(hook.Event) time.Duration { return tc.hold })
			_, held, err := NewClient(service.SocketPath()).ProcessHoldable(context.Background(), tc.event, time.Second)
			if err != nil {
				t.Fatalf("ProcessHoldable() error = %v", err)
			}
			if held {
				t.Fatal("held = true, want no hold frame")
			}
		})
	}
}

// Both copies of a doubled PreToolUse get the hold frame and the one answer.
func TestServiceHoldsBothCopiesOfADoubledHook(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{}
	runtime.evaluateCtx = func(context.Context) (hook.Result, error) {
		time.Sleep(200 * time.Millisecond)
		return hook.Result{Decision: hook.DecisionDeny, Reason: "policy"}, nil
	}
	service := newHoldService(t, runtime, func(hook.Event) time.Duration { return 400 * time.Millisecond })
	client := NewClient(service.SocketPath())
	client.Timeout = 100 * time.Millisecond

	var wg sync.WaitGroup
	results := make([]hook.Result, 2)
	helds := make([]bool, 2)
	errs := make([]error, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], helds[i], errs[i] = client.ProcessHoldable(context.Background(), preToolUse("toolu_doubled"), time.Second)
		}()
	}
	wg.Wait()
	for i := range 2 {
		if errs[i] != nil || !helds[i] || results[i].Decision != hook.DecisionDeny {
			t.Fatalf("copy %d: held = %v, decision = %q, err = %v; want held deny", i, helds[i], results[i].Decision, errs[i])
		}
	}
	if calls := runtime.evaluateCalls.Load(); calls != 1 {
		t.Fatalf("evaluations = %d, want 1 for both copies", calls)
	}
}

// fakeDaemon answers one connection with the given frames, then keeps it
// open until the test ends.
func fakeDaemon(t *testing.T, frames ...any) string {
	t.Helper()
	dir := hermetic.SocketDir(t)
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "kontext.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var req EvaluateRequest
		if err := ReadMessage(conn, &req); err != nil {
			return
		}
		for _, frame := range frames {
			if err := WriteMessage(conn, frame); err != nil {
				return
			}
		}
		<-done
	}()
	return path
}

// A daemon that predates the hold answers directly; the hook reads it as
// before.
func TestHoldableClientReadsAnOldDaemonsAnswer(t *testing.T) {
	t.Parallel()

	path := fakeDaemon(t, EvaluateResult{Type: "result", Decision: string(hook.DecisionDeny), Reason: "policy"})
	client := NewClient(path)
	client.Timeout = time.Second
	result, held, err := client.ProcessHoldable(context.Background(), preToolUse("toolu_old_daemon"), time.Second)
	if err != nil || held || result.Decision != hook.DecisionDeny {
		t.Fatalf("held = %v, decision = %q, err = %v; want an unheld deny", held, result.Decision, err)
	}
}

// A daemon that asks for a long hold and then hangs costs the hook its own
// cap plus its budget, not the daemon's number.
func TestHoldableClientCapsTheHold(t *testing.T) {
	t.Parallel()

	path := fakeDaemon(t, EvaluateResult{Type: HoldResultType, HoldMs: 60_000})
	client := NewClient(path)
	client.Timeout = 100 * time.Millisecond
	start := time.Now()
	_, held, err := client.ProcessHoldable(context.Background(), preToolUse("toolu_hung"), 200*time.Millisecond)
	took := time.Since(start)
	if err == nil || !held {
		t.Fatalf("held = %v, err = %v; want a held call that times out", held, err)
	}
	if took < 250*time.Millisecond || took > 2*time.Second {
		t.Fatalf("took %v, want about the 200 ms cap plus the 100 ms budget", took)
	}
}

func TestHoldableClientRefusesASecondHold(t *testing.T) {
	t.Parallel()

	path := fakeDaemon(t, EvaluateResult{Type: HoldResultType, HoldMs: 10}, EvaluateResult{Type: HoldResultType, HoldMs: 10})
	client := NewClient(path)
	client.Timeout = time.Second
	if _, held, err := client.ProcessHoldable(context.Background(), preToolUse("toolu_twice"), time.Second); err == nil || !held {
		t.Fatalf("held = %v, err = %v; want an error after a second hold frame", held, err)
	}
}
