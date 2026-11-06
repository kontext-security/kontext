package managedobserve

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
)

// holdingDaemon serves every connection that sends a request: it answers
// with a hold frame of holdMs, waits answerAfter, then answers deny, or
// drops the connection when drop is set. requests counts the hook calls.
func holdingDaemon(t *testing.T, holdMs int64, answerAfter time.Duration, drop bool) (string, *atomic.Int32) {
	t.Helper()
	socketPath := filepath.Join(hermetic.SocketDir(t), "kontext-managedobserve-hold.sock")
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	var requests atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req localruntime.EvaluateRequest
				if localruntime.ReadMessage(conn, &req) != nil {
					return
				}
				requests.Add(1)
				if !req.Accepts(localruntime.HoldCapability) {
					t.Errorf("PreToolUse request without the hold capability: %+v", req.Capabilities)
					return
				}
				_ = localruntime.WriteMessage(conn, localruntime.EvaluateResult{Type: localruntime.HoldResultType, HoldMs: holdMs})
				time.Sleep(answerAfter)
				if drop {
					return
				}
				_ = localruntime.WriteMessage(conn, localruntime.EvaluateResult{Decision: "deny", Reason: "Blocked by rule custom:test", Mode: "enforce"})
			}()
		}
	}()
	return socketPath, &requests
}

// A fresh daemon that holds the call until its policy arrives gets its
// decision through, although it comes after the one-second budget alone.
func TestLifecycleWaitsThroughAPolicyHold(t *testing.T) {
	socketPath, _ := holdingDaemon(t, 1500, preToolUseWait+300*time.Millisecond, false)
	lifecycle := Lifecycle{SocketPath: socketPath, Label: DefaultLaunchdLabel, Mode: "enforce", Kickstart: func(context.Context, string) error { return nil }}

	result := lifecycle.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse, ToolName: "Bash", ToolUseID: "toolu_held"})
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("result = %+v, want the held call's deny", result)
	}
}

// A held call whose daemon then goes away is not retried: it fails open
// once, instead of paying the hold and the restart wait again.
func TestLifecycleDoesNotRetryAHeldCall(t *testing.T) {
	socketPath, requests := holdingDaemon(t, 100, 50*time.Millisecond, true)
	lifecycle := Lifecycle{SocketPath: socketPath, Label: DefaultLaunchdLabel, Mode: "enforce", Kickstart: func(context.Context, string) error { return nil }}

	result := lifecycle.Process(context.Background(), hook.Event{HookName: hook.HookPreToolUse, ToolName: "Bash", ToolUseID: "toolu_dropped"})
	if result.Decision == hook.DecisionDeny {
		t.Fatalf("result = %+v, want the fail-open answer", result)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("requests = %d, want 1: a held call is not retried", got)
	}
}
