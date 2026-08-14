package sessionpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/cedarpolicy"
	"github.com/kontext-security/kontext-cli/internal/promptpolicy"
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

func TestBeginPromptSynchronouslyActivatesVerifiedPolicySet(t *testing.T) {
	parent := cedarpolicy.Deployment{DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	bundle := validBundle(t, parent.DeploymentIdentity, 1)
	deriver := &fakeDeriver{bundle: bundle}
	manager, err := NewManager(deriver, promptpolicy.NewActivationValidator(), fakeParents{cedarpolicy.Snapshot{Deployment: &parent}}, func(context.Context) (string, error) { return "token", nil }, bundle.Audience.InstallationID, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
	snapshot, err := manager.BeginPrompt(t.Context(), key, "read the report")
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Required || !snapshot.Ready || snapshot.Deployment == nil || snapshot.Deployment.PolicyText != bundle.PolicySet.Source {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if deriver.requests[0].AuthorizationSessionID != "codex:s1" {
		t.Fatalf("unexpected authorization session: %s", deriver.requests[0].AuthorizationSessionID)
	}
}

func TestNewPromptInvalidatesPriorPolicyOnFailure(t *testing.T) {
	parent := cedarpolicy.Deployment{DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	bundle := validBundle(t, parent.DeploymentIdentity, 1)
	deriver := &fakeDeriver{bundle: bundle}
	manager, _ := NewManager(deriver, promptpolicy.NewActivationValidator(), fakeParents{cedarpolicy.Snapshot{Deployment: &parent}}, func(context.Context) (string, error) { return "token", nil }, bundle.Audience.InstallationID, time.Second)
	key := SessionKey{Provider: "codex", NativeSessionID: "s1"}
	if _, err := manager.BeginPrompt(t.Context(), key, "first"); err != nil {
		t.Fatal(err)
	}
	deriver.err = errors.New("generator unavailable")
	if _, err := manager.BeginPrompt(t.Context(), key, "second"); err == nil {
		t.Fatal("expected second prompt failure")
	}
	snapshot := manager.SnapshotFor(key)
	if snapshot.PromptSequence != 2 || snapshot.Ready || snapshot.Deployment != nil {
		t.Fatalf("old policy remained eligible: %+v", snapshot)
	}
}

func validBundle(t *testing.T, parentIdentity string, sequence uint64) promptpolicy.Bundle {
	t.Helper()
	now := time.Now().UTC()
	source := `@id("kontext.generated.test") forbid(principal, action, resource);`
	digest := cedareval.ComputePolicyHash(source)
	bundle := promptpolicy.Bundle{
		ResponseVersion: 2, RequestContractVersion: 1, RolloutMode: "enforce",
		Audience:            promptpolicy.Audience{OrganizationID: "org-1", InstallationID: "ins_12345678901234567890123456789012", AuthorizationSessionID: "codex:s1", PromptSequence: sequence},
		Parent:              promptpolicy.ParentPolicySet{PolicySetVersionID: "11111111-1111-4111-8111-111111111111", PolicySetSourceHash: digest, DeploymentIdentity: parentIdentity},
		PolicySet:           promptpolicy.EffectivePolicySet{PolicySetVersionID: "22222222-2222-4222-8222-222222222222", Source: source, SourceHash: digest, StaticPolicyCount: 1},
		EvaluationPrincipal: promptpolicy.EvaluationPrincipal{EntityType: cedareval.PrincipalEntityType, EntityID: "user-1"},
		ValidFrom:           now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	identity, err := bundle.ComputeDeploymentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bundle.DeploymentIdentity = identity
	return bundle
}
