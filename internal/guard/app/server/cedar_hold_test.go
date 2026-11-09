package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/policyhold"
)

// arrivingSnapshots awaits enrolment until arrive, then reports success.
type arrivingSnapshots struct {
	arrive time.Time
	reads  atomic.Int32
}

func (s *arrivingSnapshots) Current() cedarpolicy.Snapshot {
	s.reads.Add(1)
	if time.Now().Before(s.arrive) {
		return cedarpolicy.Snapshot{State: cedarpolicy.StatePrincipalUnavailable}
	}
	return cedarpolicy.Snapshot{State: cedarpolicy.StateSuccess}
}

func TestAwaitPolicyReturnsOnceThePolicyArrives(t *testing.T) {
	snapshots := &arrivingSnapshots{arrive: time.Now().Add(60 * time.Millisecond)}
	provider := &cedarPolicyProvider{snapshots: snapshots}
	ctx := policyhold.WithDeadline(context.Background(), time.Now().Add(3*time.Second))

	start := time.Now()
	snapshot, stopped := provider.awaitPolicy(ctx)
	took := time.Since(start)
	if stopped || snapshot.State != cedarpolicy.StateSuccess {
		t.Fatalf("state = %q, stopped = %v; want the arrived policy", snapshot.State, stopped)
	}
	if took > time.Second {
		t.Fatalf("took %v, want soon after the policy arrived, not the hold's end", took)
	}
}

func TestAwaitPolicyGivesUpAtTheHoldsEnd(t *testing.T) {
	provider := &cedarPolicyProvider{snapshots: &arrivingSnapshots{arrive: time.Now().Add(time.Hour)}}
	ctx := policyhold.WithDeadline(context.Background(), time.Now().Add(100*time.Millisecond))

	start := time.Now()
	snapshot, stopped := provider.awaitPolicy(ctx)
	took := time.Since(start)
	if stopped || snapshot.State != cedarpolicy.StatePrincipalUnavailable {
		t.Fatalf("state = %q, stopped = %v; want the unenrolled state at the hold's end", snapshot.State, stopped)
	}
	if took < 90*time.Millisecond || took > time.Second {
		t.Fatalf("took %v, want about the 100 ms hold", took)
	}
}

func TestAwaitPolicyWithoutAHoldNeverWaits(t *testing.T) {
	snapshots := &arrivingSnapshots{arrive: time.Now().Add(time.Hour)}
	provider := &cedarPolicyProvider{snapshots: snapshots}

	snapshot, stopped := provider.awaitPolicy(context.Background())
	if stopped || snapshot.State != cedarpolicy.StatePrincipalUnavailable || snapshots.reads.Load() != 1 {
		t.Fatalf("state = %q, reads = %d, stopped = %v; want one read and no wait", snapshot.State, snapshots.reads.Load(), stopped)
	}
}

func TestAwaitPolicyDoesNotWaitOnceEnrolled(t *testing.T) {
	for _, state := range []cedarpolicy.State{cedarpolicy.StateSuccess, cedarpolicy.StateNoActivePolicy, cedarpolicy.StateDisabled, cedarpolicy.StateUnavailable} {
		provider := &cedarPolicyProvider{snapshots: staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: state}}}
		ctx := policyhold.WithDeadline(context.Background(), time.Now().Add(time.Hour))
		start := time.Now()
		if _, stopped := provider.awaitPolicy(ctx); stopped || time.Since(start) > 100*time.Millisecond {
			t.Fatalf("state %q: stopped = %v, took %v; want no wait", state, stopped, time.Since(start))
		}
	}
}

// A cancelled hold stops waiting and hands back the current snapshot, so the
// call is decided as at the hold's end.
func TestAwaitPolicyStopsWhenTheCallIsCancelled(t *testing.T) {
	provider := &cedarPolicyProvider{snapshots: &arrivingSnapshots{arrive: time.Now().Add(time.Hour)}}
	ctx, cancel := context.WithCancel(policyhold.WithDeadline(context.Background(), time.Now().Add(time.Hour)))
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	snapshot, stopped := provider.awaitPolicy(ctx)
	if !stopped || snapshot.State != cedarpolicy.StatePrincipalUnavailable || time.Since(start) > time.Second {
		t.Fatalf("stopped = %v, state = %q after %v; want a stop with the current snapshot", stopped, snapshot.State, time.Since(start))
	}
}
