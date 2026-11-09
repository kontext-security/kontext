package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/localruntime"
)

// arrivingDeployment awaits enrolment until arrive, then serves deployment.
type arrivingDeployment struct {
	arrive     time.Time
	deployment cedarpolicy.Deployment
}

func (s arrivingDeployment) Current() cedarpolicy.Snapshot {
	if time.Now().Before(s.arrive) {
		return cedarpolicy.Snapshot{State: cedarpolicy.StatePrincipalUnavailable}
	}
	return cedarpolicy.Snapshot{State: cedarpolicy.StateSuccess, Deployment: &s.deployment, LastKnownGood: &s.deployment}
}

// holdingDaemon runs the real server and local runtime over a socket, with a
// policy that forbids Write once it arrives after arriveAfter, and holds
// calls while enrolment is awaited, until hold after start.
func holdingDaemon(t *testing.T, arriveAfter, hold time.Duration) string {
	t.Helper()
	return holdingDaemonIn(t, context.Background(), arriveAfter, hold)
}

// holdingDaemonIn is holdingDaemon serving in ctx, as the daemon serves in
// its signal-cancelled context.
func holdingDaemonIn(t *testing.T, ctx context.Context, arriveAfter, hold time.Duration) string {
	t.Helper()
	store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	started := time.Now()
	policies := arrivingDeployment{
		arrive: started.Add(arriveAfter),
		deployment: cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("allow") permit(principal, action, resource);
@id("write-block") forbid(principal, action, resource == Kontext::Tool::"Write");`),
	}
	srv, err := NewServerWithPolicyAndOptions(store, nil, Options{CedarPolicies: policies, CedarEnforcement: CedarEnforcementRemote})
	if err != nil {
		t.Fatal(err)
	}
	service, err := localruntime.NewService(localruntime.Options{
		SocketPath: filepath.Join(hermetic.SocketDir(t), "s.sock"),
		Core:       srv.RuntimeCore(),
		HoldFor: func(event hook.Event) time.Duration {
			remaining := time.Until(started.Add(hold))
			if remaining <= 0 || !cedarpolicy.AwaitingEnrolment(policies.Current().State) {
				return 0
			}
			return remaining
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Stop)
	return service.SocketPath()
}

func writeCall(id string) hook.Event {
	return hook.Event{SessionID: "hold", Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Write", ToolUseID: id, ToolInput: map[string]any{"file_path": "/tmp/x", "content": "x"}}
}

// ENG-939 end to end through the real server: a fresh daemon holds the
// first call past the hook's one-second budget until the policy arrives,
// and the policy decides it.
func TestHeldCallIsDecidedByThePolicyThatArrives(t *testing.T) {
	socket := holdingDaemon(t, 1300*time.Millisecond, 3*time.Second)
	client := localruntime.NewClient(socket)
	client.Timeout = time.Second

	start := time.Now()
	result, held, err := client.ProcessHoldable(context.Background(), writeCall("toolu_first"), 3*time.Second)
	took := time.Since(start)
	if err != nil || !held {
		t.Fatalf("held = %v, err = %v; want a held call that is answered", held, err)
	}
	if result.Decision != hook.DecisionDeny {
		t.Fatalf("Decision = %q (%s), want the arrived policy's deny", result.Decision, result.Reason)
	}
	if took < 1200*time.Millisecond || took > 2500*time.Millisecond {
		t.Fatalf("took %v, want soon after the policy arrived at 1.3 s", took)
	}

	// Once the policy is there, nothing is held.
	result, held, err = client.ProcessHoldable(context.Background(), writeCall("toolu_second"), 3*time.Second)
	if err != nil || held || result.Decision != hook.DecisionDeny {
		t.Fatalf("second call: held = %v, decision = %q, err = %v; want an unheld deny", held, result.Decision, err)
	}
}

// When the policy does not arrive within the hold, the call is decided as
// before the change: with no policy, the remote posture lets it through.
func TestHeldCallIsLetThroughWhenTheHoldEnds(t *testing.T) {
	socket := holdingDaemon(t, time.Hour, 300*time.Millisecond)
	client := localruntime.NewClient(socket)
	client.Timeout = time.Second

	start := time.Now()
	result, held, err := client.ProcessHoldable(context.Background(), writeCall("toolu_timeout"), 3*time.Second)
	took := time.Since(start)
	if err != nil || !held {
		t.Fatalf("held = %v, err = %v; want a held call that is answered", held, err)
	}
	if result.Decision == hook.DecisionDeny {
		t.Fatalf("Decision = deny (%s), want the call let through at the hold's end", result.Reason)
	}
	if took < 250*time.Millisecond || took > 1500*time.Millisecond {
		t.Fatalf("took %v, want about the 300 ms hold", took)
	}
}

// A hook that predates the hold is answered at once, as before: the daemon
// neither holds nor sends a frame it cannot read.
func TestOldHookIsNotHeld(t *testing.T) {
	socket := holdingDaemon(t, 1300*time.Millisecond, 3*time.Second)
	client := localruntime.NewClient(socket)
	client.Timeout = time.Second

	start := time.Now()
	result, err := client.Process(context.Background(), writeCall("toolu_old"))
	if err != nil {
		t.Fatalf("Process() error = %v", err)
	}
	if took := time.Since(start); took > 500*time.Millisecond {
		t.Fatalf("took %v, want an immediate answer", took)
	}
	if result.Decision == hook.DecisionDeny {
		t.Fatalf("Decision = deny before the policy arrived; want today's answer without a policy")
	}
}

// A daemon stopping during a hold (SIGTERM, a kickstart replacing the
// binary) ends the hold early: the call is decided as when the hold runs
// out, not denied because the evaluation was cancelled.
func TestHeldCallIsDecidedWhenTheDaemonStops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := holdingDaemonIn(t, ctx, time.Hour, 3*time.Second)
	client := localruntime.NewClient(socket)
	client.Timeout = time.Second

	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	result, held, err := client.ProcessHoldable(context.Background(), writeCall("toolu_stopping"), 3*time.Second)
	if err != nil || !held {
		t.Fatalf("held = %v, err = %v; want a held call that is answered", held, err)
	}
	if result.Decision == hook.DecisionDeny {
		t.Fatalf("Decision = deny (%s), want the call let through as at the hold's end", result.Reason)
	}
	if took := time.Since(start); took > 1500*time.Millisecond {
		t.Fatalf("took %v, want soon after the daemon stopped at 200 ms", took)
	}
}
