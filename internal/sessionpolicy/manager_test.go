package sessionpolicy

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/promptpolicy"
)

type fakeDeriver struct {
	bundle   promptpolicy.Bundle
	err      error
	requests []promptpolicy.Request
}

func (f *fakeDeriver) Put(_ context.Context, request promptpolicy.Request) (promptpolicy.Bundle, error) {
	f.requests = append(f.requests, request)
	return f.bundle, f.err
}

type fakeParents struct{ snapshot cedarpolicy.Snapshot }

func (f fakeParents) Current() cedarpolicy.Snapshot { return f.snapshot }

type mutableParents struct{ snapshot cedarpolicy.Snapshot }

func (f *mutableParents) Current() cedarpolicy.Snapshot { return f.snapshot }

type firstBlockingDeriver struct {
	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

type blockingBundleDeriver struct {
	bundle  promptpolicy.Bundle
	started chan struct{}
	release chan struct{}
}

func (d *blockingBundleDeriver) Put(context.Context, promptpolicy.Request) (promptpolicy.Bundle, error) {
	close(d.started)
	<-d.release
	return d.bundle, nil
}

type flakyTransportDeriver struct {
	bundle promptpolicy.Bundle
	calls  int
}

func (d *flakyTransportDeriver) Put(context.Context, promptpolicy.Request) (promptpolicy.Bundle, error) {
	d.calls++
	if d.calls < 3 {
		return promptpolicy.Bundle{}, &promptpolicy.TransportError{Err: errors.New("connection reset")}
	}
	return d.bundle, nil
}

func (d *firstBlockingDeriver) Put(context.Context, promptpolicy.Request) (promptpolicy.Bundle, error) {
	if d.calls.Add(1) == 1 {
		close(d.started)
		<-d.release
	}
	return promptpolicy.Bundle{}, errors.New("generation unavailable")
}

func TestBeginPromptSynchronouslyActivatesVerifiedPolicySet(t *testing.T) {
	parent := cedarpolicy.Deployment{DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	bundle := validBundle(t, parent.DeploymentIdentity, 1)
	deriver := &fakeDeriver{bundle: bundle}
	manager, err := NewManager(deriver, promptpolicy.NewActivationValidator(), fakeParents{cedarpolicy.Snapshot{Deployment: &parent, State: cedarpolicy.StateSuccess}}, func(context.Context) (string, error) { return "token", nil }, bundle.Audience.InstallationID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	manager.SetEnabled(true)
	manager.daemonEpoch = "test"
	bundle.Audience.AuthorizationSessionID = "codex:s1:test"
	refreshIdentity(t, &bundle)
	deriver.bundle = bundle
	key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
	snapshot, err := manager.BeginPrompt(t.Context(), key, "read the report")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.State != SessionStateActive || snapshot.PolicySet == nil || snapshot.PolicySet.Source != bundle.PolicySet.Source {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if deriver.requests[0].AuthorizationSessionID != "codex:s1:test" {
		t.Fatalf("unexpected authorization session: %s", deriver.requests[0].AuthorizationSessionID)
	}
}

func TestSessionPolicyFollowsGeneratedRolloutMode(t *testing.T) {
	for _, test := range []struct {
		name        string
		rolloutMode cedareval.RolloutMode
		wantEnforce bool
	}{
		{name: "observe", rolloutMode: cedareval.RolloutModeObserve},
		{name: "enforce", rolloutMode: cedareval.RolloutModeEnforce, wantEnforce: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent := cedarpolicy.Deployment{
				DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				RolloutMode:        test.rolloutMode,
			}
			bundle := validBundle(t, parent.DeploymentIdentity, 1)
			bundle.RolloutMode = string(test.rolloutMode)
			bundle.Audience.AuthorizationSessionID = "codex:s1:test"
			refreshIdentity(t, &bundle)
			manager, err := NewManager(
				&fakeDeriver{bundle: bundle},
				promptpolicy.NewActivationValidator(),
				fakeParents{snapshot: cedarpolicy.Snapshot{Deployment: &parent, State: cedarpolicy.StateSuccess}},
				func(context.Context) (string, error) { return "token", nil },
				bundle.Audience.InstallationID,
				time.Second,
			)
			if err != nil {
				t.Fatal(err)
			}
			manager.SetEnabled(true)
			manager.daemonEpoch = "test"
			key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
			if _, err := manager.BeginPrompt(t.Context(), key, "read"); err != nil {
				t.Fatal(err)
			}

			current := manager.CurrentFor(key.NativeSessionID, key.Provider)
			if got := cedarpolicy.DeploymentClaimsEnforce(current); got != test.wantEnforce {
				t.Fatalf("DeploymentClaimsEnforce() = %t, want %t; snapshot = %+v", got, test.wantEnforce, current)
			}
		})
	}
}

func TestNewPromptInvalidatesPriorPolicyOnFailure(t *testing.T) {
	parent := cedarpolicy.Deployment{DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	bundle := validBundle(t, parent.DeploymentIdentity, 1)
	deriver := &fakeDeriver{bundle: bundle}
	manager, _ := NewManager(deriver, promptpolicy.NewActivationValidator(), fakeParents{cedarpolicy.Snapshot{Deployment: &parent, State: cedarpolicy.StateSuccess}}, func(context.Context) (string, error) { return "token", nil }, bundle.Audience.InstallationID, time.Second)
	manager.SetEnabled(true)
	manager.daemonEpoch = "test"
	bundle.Audience.AuthorizationSessionID = "codex:s1:test"
	refreshIdentity(t, &bundle)
	deriver.bundle = bundle
	key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
	if _, err := manager.BeginPrompt(t.Context(), key, "first"); err != nil {
		t.Fatal(err)
	}
	deriver.err = errors.New("generator unavailable")
	if _, err := manager.BeginPrompt(t.Context(), key, "second"); err == nil {
		t.Fatal("expected second prompt failure")
	}
	snapshot := manager.SnapshotFor(key)
	if snapshot.PromptSequence != 2 || snapshot.State != SessionStateFailed || snapshot.PolicySet != nil {
		t.Fatalf("old policy remained eligible: %+v", snapshot)
	}
}

func TestBeginPromptRetriesIdempotentTransportFailures(t *testing.T) {
	parent := cedarpolicy.Deployment{DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	bundle := validBundle(t, parent.DeploymentIdentity, 1)
	bundle.Audience.AuthorizationSessionID = "codex:s1:test"
	refreshIdentity(t, &bundle)
	deriver := &flakyTransportDeriver{bundle: bundle}
	manager, _ := NewManager(deriver, promptpolicy.NewActivationValidator(), fakeParents{cedarpolicy.Snapshot{Deployment: &parent, State: cedarpolicy.StateSuccess}}, func(context.Context) (string, error) { return "token", nil }, bundle.Audience.InstallationID, time.Second)
	manager.SetEnabled(true)
	manager.daemonEpoch = "test"

	snapshot, err := manager.BeginPrompt(t.Context(), SessionKey{Provider: "codex", NativeSessionID: "s1"}, "read")
	if err != nil {
		t.Fatal(err)
	}
	if deriver.calls != 3 || snapshot.State != SessionStateActive {
		t.Fatalf("calls = %d snapshot = %+v", deriver.calls, snapshot)
	}
}

func TestOrganizationDeploymentChangeInvalidatesSessionPolicy(t *testing.T) {
	parent := cedarpolicy.Deployment{DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	parents := &mutableParents{snapshot: cedarpolicy.Snapshot{Deployment: &parent, State: cedarpolicy.StateSuccess}}
	bundle := validBundle(t, parent.DeploymentIdentity, 1)
	manager, _ := NewManager(&fakeDeriver{bundle: bundle}, promptpolicy.NewActivationValidator(), parents, func(context.Context) (string, error) { return "token", nil }, bundle.Audience.InstallationID, time.Second)
	manager.SetEnabled(true)
	manager.daemonEpoch = "test"
	bundle.Audience.AuthorizationSessionID = "codex:s1:test"
	refreshIdentity(t, &bundle)
	manager.deriver = &fakeDeriver{bundle: bundle}
	key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
	if _, err := manager.BeginPrompt(t.Context(), key, "first"); err != nil {
		t.Fatal(err)
	}
	replacement := parent
	replacement.DeploymentIdentity = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	parents.snapshot = cedarpolicy.Snapshot{Deployment: &replacement, State: cedarpolicy.StateSuccess}
	if snapshot := manager.CurrentFor(key.NativeSessionID, key.Provider); snapshot.Deployment != nil || !snapshot.Status.Invalid {
		t.Fatalf("session policy survived parent replacement: %+v", snapshot)
	}
}

func TestNonSuccessParentCannotReactivateLastKnownSessionPolicy(t *testing.T) {
	parent := cedarpolicy.Deployment{DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	parents := &mutableParents{snapshot: cedarpolicy.Snapshot{Deployment: &parent, State: cedarpolicy.StateSuccess}}
	bundle := validBundle(t, parent.DeploymentIdentity, 1)
	manager, _ := NewManager(&fakeDeriver{bundle: bundle}, promptpolicy.NewActivationValidator(), parents, func(context.Context) (string, error) { return "token", nil }, bundle.Audience.InstallationID, time.Second)
	manager.SetEnabled(true)
	manager.daemonEpoch = "test"
	bundle.Audience.AuthorizationSessionID = "codex:s1:test"
	refreshIdentity(t, &bundle)
	manager.deriver = &fakeDeriver{bundle: bundle}
	key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
	if _, err := manager.BeginPrompt(t.Context(), key, "first"); err != nil {
		t.Fatal(err)
	}
	parents.snapshot = cedarpolicy.Snapshot{LastKnownGood: &parent, State: cedarpolicy.StatePrincipalUnavailable}
	snapshot := manager.CurrentFor(key.NativeSessionID, key.Provider)
	if !snapshot.Status.Invalid || snapshot.PolicySet != nil || snapshot.ActivePolicySet() != nil {
		t.Fatalf("non-success parent reactivated a stale session policy: %+v", snapshot)
	}
}

func TestNewPromptPublishesBarrierBeforePriorGenerationFinishes(t *testing.T) {
	parent := cedarpolicy.Deployment{DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", RolloutMode: cedareval.RolloutModeObserve}
	deriver := &firstBlockingDeriver{started: make(chan struct{}), release: make(chan struct{})}
	manager, _ := NewManager(deriver, promptpolicy.NewActivationValidator(), fakeParents{cedarpolicy.Snapshot{Deployment: &parent, State: cedarpolicy.StateSuccess}}, func(context.Context) (string, error) { return "token", nil }, "ins_12345678901234567890123456789012", time.Second)
	manager.SetEnabled(true)
	key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		_, _ = manager.BeginPrompt(t.Context(), key, "first")
	}()
	<-deriver.started
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		_, _ = manager.BeginPrompt(t.Context(), key, "second")
	}()

	deadline := time.Now().Add(time.Second)
	for manager.SnapshotFor(key).PromptSequence != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	snapshot := manager.SnapshotFor(key)
	if snapshot.PromptSequence != 2 || snapshot.State != SessionStatePending {
		t.Fatalf("second prompt did not publish its barrier: %+v", snapshot)
	}
	if current := manager.CurrentFor(key.NativeSessionID, key.Provider); !current.Status.Invalid || cedarpolicy.DeploymentClaimsEnforce(current) {
		t.Fatalf("pending observe policy became authoritative: %+v", current)
	}
	close(deriver.release)
	<-firstDone
	<-secondDone
}

func TestMissingRequiredPolicyPreservesParentEnforcementClaim(t *testing.T) {
	parent := cedarpolicy.Deployment{
		DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RolloutMode:        cedareval.RolloutModeEnforce,
	}
	manager, _ := NewManager(
		&fakeDeriver{err: errors.New("unavailable")},
		promptpolicy.NewActivationValidator(),
		&mutableParents{snapshot: cedarpolicy.Snapshot{LastKnownGood: &parent, State: cedarpolicy.StateUnavailable}},
		func(context.Context) (string, error) { return "token", nil },
		"ins_12345678901234567890123456789012",
		time.Second,
	)
	manager.SetEnabled(true)
	key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
	state := manager.sessionFor(key)
	state.snapshot = Snapshot{State: SessionStatePending, PromptSequence: 1}
	snapshot := manager.CurrentFor(key.NativeSessionID, key.Provider)
	if snapshot.LastKnownGood == nil || !cedarpolicy.DeploymentClaimsEnforce(snapshot) {
		t.Fatalf("parent enforce claim was lost: %+v", snapshot)
	}
}

func TestExplicitOrganizationDisableKeepsPromptBarrierClosed(t *testing.T) {
	parent := cedarpolicy.Deployment{
		DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		RolloutMode:        cedareval.RolloutModeEnforce,
	}
	parents := &mutableParents{snapshot: cedarpolicy.Snapshot{State: cedarpolicy.StateDisabled, LastKnownGood: &parent}}
	manager, _ := NewManager(
		&fakeDeriver{}, promptpolicy.NewActivationValidator(), parents,
		func(context.Context) (string, error) { return "token", nil },
		"ins_12345678901234567890123456789012", time.Second,
	)
	manager.SetEnabled(true)
	key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
	state := manager.sessionFor(key)
	state.snapshot = Snapshot{
		State: SessionStateActive, PromptSequence: 1,
		PolicySet:                &cedarpolicy.PolicySetSnapshot{RolloutMode: "enforce"},
		ParentDeploymentIdentity: parent.DeploymentIdentity,
		ExpiresAt:                time.Now().Add(time.Hour),
	}
	snapshot := manager.CurrentFor(key.NativeSessionID, key.Provider)
	if !snapshot.Status.Invalid || !cedarpolicy.DeploymentClaimsEnforce(snapshot) {
		t.Fatalf("explicit disable opened the prompt barrier: %+v", snapshot)
	}
}

func TestDisableDiscardsAnInFlightPromptPolicy(t *testing.T) {
	parent := cedarpolicy.Deployment{DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	bundle := validBundle(t, parent.DeploymentIdentity, 1)
	bundle.Audience.AuthorizationSessionID = "codex:s1:test"
	refreshIdentity(t, &bundle)
	deriver := &blockingBundleDeriver{bundle: bundle, started: make(chan struct{}), release: make(chan struct{})}
	manager, _ := NewManager(
		deriver,
		promptpolicy.NewActivationValidator(),
		fakeParents{snapshot: cedarpolicy.Snapshot{Deployment: &parent, State: cedarpolicy.StateSuccess}},
		func(context.Context) (string, error) { return "token", nil },
		bundle.Audience.InstallationID,
		time.Second,
	)
	manager.daemonEpoch = "test"
	manager.SetEnabled(true)
	key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = manager.BeginPrompt(t.Context(), key, "read")
	}()
	<-deriver.started
	manager.SetEnabled(false)
	close(deriver.release)
	<-done
	manager.SetEnabled(true)

	if snapshot := manager.SnapshotFor(key); snapshot.State != SessionStateIdle {
		t.Fatalf("disabled in-flight policy was resurrected: %+v", snapshot)
	}
	if current := manager.CurrentFor(key.NativeSessionID, key.Provider); !current.Status.Invalid || cedarpolicy.DeploymentClaimsEnforce(current) {
		t.Fatalf("re-enabled session did not require a fresh prompt: %+v", current)
	}
}

func validBundle(t *testing.T, parentIdentity string, sequence uint64) promptpolicy.Bundle {
	t.Helper()
	now := time.Now().UTC()
	source := `@id("kontext.generated.test") forbid(principal, action, resource);`
	digest := cedareval.ComputePolicyHash(source)
	bundle := promptpolicy.Bundle{
		ResponseVersion: 2, CedarRequestContractVersion: 1, RolloutMode: "enforce",
		Audience:            promptpolicy.Audience{OrganizationID: "org-1", InstallationID: "ins_12345678901234567890123456789012", AuthorizationSessionID: "codex:s1", PromptSequence: sequence},
		Parent:              promptpolicy.ParentPolicySet{PolicySetVersionID: "11111111-1111-4111-8111-111111111111", PolicySetSourceHash: digest, DeploymentIdentity: parentIdentity},
		PolicySet:           promptpolicy.EffectivePolicySet{PolicySetVersionID: "22222222-2222-4222-8222-222222222222", Source: source, SourceHash: digest, StaticPolicyCount: 1},
		EvaluationPrincipal: promptpolicy.EvaluationPrincipal{EntityType: cedareval.PrincipalEntityType, EntityID: "user-1"},
		ValidFrom:           now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	refreshIdentity(t, &bundle)
	return bundle
}

func refreshIdentity(t *testing.T, bundle *promptpolicy.Bundle) {
	t.Helper()
	identity, err := bundle.ComputeDeploymentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bundle.DeploymentIdentity = identity
}
