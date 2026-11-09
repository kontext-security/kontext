package managedobserve

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/app/server"
	guardhookruntime "github.com/kontext-security/kontext/internal/guard/hookruntime"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/runtimehost"
)

const stackTestSchema = `namespace Kontext {
  entity Endpoint;
  entity Agent;
  entity Tool;
  action "ToolUse" appliesTo {
    principal: [Endpoint],
    resource: [Tool],
    context: {}
  };
}`

const stackTestToolCatalogDigest = "b28108efc334761c791b00953e51e682568faa911be4c5c9c14bab48e987b13d"

// writeBlockDeployment allows everything except the Write tool.
func writeBlockDeployment(t *testing.T) cedarpolicy.Deployment {
	t.Helper()
	policy := `@id("allow") permit(principal, action, resource);
@id("write-block") forbid(principal, action, resource == Kontext::Tool::"Write");`
	principal := cedareval.EvaluationPrincipal{EntityType: cedareval.EndpointEntityTypeV2, EntityID: "ins_12345678901234567890123456789012"}
	policyHash := cedareval.ComputePolicyHash(policy)
	schemaHash := cedareval.ComputeSchemaHash(stackTestSchema)
	identity, err := cedareval.ComputeDeploymentIdentityV2(cedareval.DeploymentIdentityV2Input{
		ResponseVersion:        cedarpolicy.ResponseVersion,
		RequestContractVersion: cedarpolicy.RequestContractVersion,
		PolicySetSourceHash:    policyHash,
		SchemaHash:             schemaHash,
		ToolCatalogDigest:      stackTestToolCatalogDigest,
		RolloutMode:            string(cedareval.RolloutModeEnforce),
		EvaluationPrincipal:    principal,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cedarpolicy.Deployment{
		ResponseVersion:        cedarpolicy.ResponseVersion,
		RequestContractVersion: cedarpolicy.RequestContractVersion,
		PolicySet:              cedarpolicy.PolicySet{Source: policy, SourceHash: policyHash},
		Schema:                 cedarpolicy.Schema{Source: stackTestSchema, Hash: schemaHash},
		ToolCatalogDigest:      stackTestToolCatalogDigest,
		RolloutMode:            cedareval.RolloutModeEnforce,
		EvaluationPrincipal:    principal,
		DeploymentIdentity:     identity,
	}
}

// arrivingPolicy awaits enrolment until arrive (Unix nanoseconds), then
// serves deployment.
type arrivingPolicy struct {
	arrive     atomic.Int64
	deployment cedarpolicy.Deployment
}

func (s *arrivingPolicy) Current() cedarpolicy.Snapshot {
	if time.Now().UnixNano() < s.arrive.Load() {
		return cedarpolicy.Snapshot{State: cedarpolicy.StatePrincipalUnavailable}
	}
	return cedarpolicy.Snapshot{State: cedarpolicy.StateSuccess, Deployment: &s.deployment, LastKnownGood: &s.deployment}
}

// startHoldingHost runs the daemon's real runtime host, as RunDaemon wires
// it, with the hold of wait from its start and a policy that arrives
// arriveAfter once the host is up. It returns the socket and when the host
// was up.
func startHoldingHost(t *testing.T, mode guardhookruntime.Mode, arriveAfter, wait time.Duration) (string, time.Time) {
	t.Helper()
	return startHoldingHostIn(t, context.Background(), mode, arriveAfter, wait)
}

// startHoldingHostIn is startHoldingHost serving in ctx, as RunDaemon serves
// in its signal-cancelled context.
func startHoldingHostIn(t *testing.T, ctx context.Context, mode guardhookruntime.Mode, arriveAfter, wait time.Duration) (string, time.Time) {
	t.Helper()
	t.Setenv("KONTEXT_STEP_SAFETY_SHADOW", "0")
	enforcement := server.CedarEnforcementStatic
	if mode == guardhookruntime.ModeRemote {
		enforcement = server.CedarEnforcementRemote
	}
	started := time.Now()
	policies := &arrivingPolicy{deployment: writeBlockDeployment(t)}
	policies.arrive.Store(started.Add(time.Hour).UnixNano())
	host, err := runtimehost.Start(ctx, runtimehost.Options{
		AgentName:          "claude",
		CWD:                t.TempDir(),
		DBPath:             filepath.Join(t.TempDir(), "guard.db"),
		SocketPath:         filepath.Join(hermetic.SocketDir(t), "kontext.sock"),
		CedarPolicies:      policies,
		CedarEnforcement:   enforcement,
		Mode:               mode,
		SkipInitialSession: true,
		HoldFor:            enrolmentHold(started, wait, enforcement, policies),
	})
	if err != nil {
		t.Fatalf("runtimehost.Start() error = %v", err)
	}
	t.Cleanup(func() { _ = host.Close(context.Background()) })
	up := time.Now()
	policies.arrive.Store(up.Add(arriveAfter).UnixNano())
	return host.SocketPath, up
}

func stackWriteCall(id string) hook.Event {
	return hook.Event{SessionID: "stack", Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Write", ToolUseID: id, ToolInput: map[string]any{"file_path": "/tmp/x", "content": "x"}}
}

// ENG-939 from the hook down: Lifecycle.Process against the daemon's real
// runtime host, in both postures that can block. The first call is held past
// the one-second budget and denied by the policy that arrives; when the hold
// ends first, the call is let through as before.
func TestHookHeldUntilThePolicyArrives(t *testing.T) {
	for _, mode := range []guardhookruntime.Mode{guardhookruntime.ModeEnforce, guardhookruntime.ModeRemote} {
		t.Run(string(mode), func(t *testing.T) {
			socket, _ := startHoldingHost(t, mode, 1300*time.Millisecond, 3*time.Second)
			lifecycle := Lifecycle{SocketPath: socket, Label: DefaultLaunchdLabel, Mode: string(mode), Kickstart: func(context.Context, string) error { return nil }}

			start := time.Now()
			result := lifecycle.Process(context.Background(), stackWriteCall("toolu_first"))
			took := time.Since(start)
			if result.Decision != hook.DecisionDeny || result.FailedOpen {
				t.Fatalf("result = %+v, want the arrived policy's deny", result)
			}
			if took < 1200*time.Millisecond || took > 2500*time.Millisecond {
				t.Fatalf("took %v, want soon after the policy arrived at 1.3 s", took)
			}

			start = time.Now()
			result = lifecycle.Process(context.Background(), stackWriteCall("toolu_second"))
			if result.Decision != hook.DecisionDeny || time.Since(start) > 500*time.Millisecond {
				t.Fatalf("second call = %+v after %v, want an immediate deny", result, time.Since(start))
			}
		})
	}
}

func TestHookLetThroughWhenTheHoldEnds(t *testing.T) {
	for _, mode := range []guardhookruntime.Mode{guardhookruntime.ModeEnforce, guardhookruntime.ModeRemote} {
		t.Run(string(mode), func(t *testing.T) {
			// The hold counts from daemon start, so make it outlast the host's
			// start-up and check the call came back at about its end.
			socket, up := startHoldingHost(t, mode, time.Hour, 2*time.Second)
			lifecycle := Lifecycle{SocketPath: socket, Label: DefaultLaunchdLabel, Mode: string(mode), Kickstart: func(context.Context, string) error { return nil }}

			start := time.Now()
			result := lifecycle.Process(context.Background(), stackWriteCall("toolu_timeout"))
			took := time.Since(start)
			if result.Decision == hook.DecisionDeny {
				t.Fatalf("result = %+v, want the call let through at the hold's end", result)
			}
			if took < time.Second || took > 2500*time.Millisecond {
				t.Fatalf("took %v (host up %v before the call), want about the rest of the 2 s hold", took, start.Sub(up))
			}
		})
	}
}

// A daemon stopping during a hold (SIGTERM, a kickstart replacing the
// binary) lets the held call through as at the hold's end, in both postures
// that can block, instead of denying it as an evaluation failure.
func TestHookHeldWhileTheDaemonStopsIsLetThrough(t *testing.T) {
	for _, mode := range []guardhookruntime.Mode{guardhookruntime.ModeEnforce, guardhookruntime.ModeRemote} {
		t.Run(string(mode), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			socket, _ := startHoldingHostIn(t, ctx, mode, time.Hour, 3*time.Second)
			lifecycle := Lifecycle{SocketPath: socket, Label: DefaultLaunchdLabel, Mode: string(mode), Kickstart: func(context.Context, string) error { return nil }}

			time.AfterFunc(200*time.Millisecond, cancel)
			result := lifecycle.Process(context.Background(), stackWriteCall("toolu_stopping"))
			if result.Decision == hook.DecisionDeny {
				t.Fatalf("result = %+v, want the call let through when the daemon stops during the hold", result)
			}
		})
	}
}
