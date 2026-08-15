package promptpolicy

import (
	"testing"
	"time"
)

func TestActivationValidatorAcceptsExactBundleAndRejectsTampering(t *testing.T) {
	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.UTC)
	bundle := testBundle(t, now)
	validator := NewActivationValidator()
	validator.now = func() time.Time { return now }
	expected := ExpectedAudience{
		OrganizationID: "org-1", InstallationID: "ins_12345678901234567890123456789012",
		AuthorizationSessionID: "codex-session-1", PromptSequence: 3,
		ParentDeploymentIdentity: bundle.Parent.DeploymentIdentity,
		RolloutMode:              bundle.RolloutMode,
	}
	if err := validator.Validate(bundle, expected); err != nil {
		t.Fatalf("validate bundle: %v", err)
	}

	tampered := bundle
	tampered.PolicySet.Source += "\nforbid(principal, action, resource);"
	if err := validator.Validate(tampered, expected); err == nil {
		t.Fatal("expected tampered source to be rejected")
	}
	wrongSession := expected
	wrongSession.AuthorizationSessionID = "codex-session-2"
	if err := validator.Validate(bundle, wrongSession); err == nil {
		t.Fatal("expected audience mismatch to be rejected")
	}
	wrongRollout := expected
	wrongRollout.RolloutMode = "observe"
	if err := validator.Validate(bundle, wrongRollout); err == nil {
		t.Fatal("expected rollout mismatch to be rejected")
	}
}

func TestDecodeBundleRejectsUnknownAndTrailingJSON(t *testing.T) {
	for _, input := range []string{
		`{"unknown":true}`,
		`{} {}`,
	} {
		if _, err := DecodeBundle([]byte(input)); err == nil {
			t.Fatalf("expected strict decode failure for %q", input)
		}
	}
}

func TestDeploymentIdentityMatchesTypeScriptFixture(t *testing.T) {
	source := `@id("kontext.generated.fixture") forbid(principal, action, resource);`
	digest := sourceHash(source)
	bundle := Bundle{
		ResponseVersion: ResponseVersion, CedarRequestContractVersion: CedarRequestVersion,
		RolloutMode:         "enforce",
		Audience:            Audience{OrganizationID: "org_fixture", InstallationID: "ins_0123456789abcdefghijklmnopqrstuv", AuthorizationSessionID: "codex:session:epoch", PromptSequence: 1},
		Parent:              ParentPolicySet{PolicySetVersionID: "11111111-1111-4111-8111-111111111111", PolicySetSourceHash: digest, DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		PolicySet:           EffectivePolicySet{PolicySetVersionID: "22222222-2222-4222-8222-222222222222", Source: source, SourceHash: digest, StaticPolicyCount: 1},
		EvaluationPrincipal: EvaluationPrincipal{EntityType: "Kontext::User", EntityID: "user-fixture"},
		ValidFrom:           "2026-08-15T10:00:00.000Z", ExpiresAt: "2026-08-15T11:00:00.000Z",
	}
	identity, err := bundle.ComputeDeploymentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	const expected = "817e35fb0e6018c6bf9e50e143be55df2ae23e1a07a5786e9aa2b1bc3e353e31"
	if identity != expected {
		t.Fatalf("identity = %s, want %s", identity, expected)
	}
}

func testBundle(t *testing.T, now time.Time) Bundle {
	t.Helper()
	source := `permit(principal, action, resource);`
	bundle := Bundle{
		ResponseVersion: ResponseVersion, CedarRequestContractVersion: CedarRequestVersion,
		RolloutMode:         "enforce",
		Audience:            Audience{OrganizationID: "org-1", InstallationID: "ins_12345678901234567890123456789012", AuthorizationSessionID: "codex-session-1", PromptSequence: 3},
		Parent:              ParentPolicySet{PolicySetVersionID: "11111111-1111-4111-8111-111111111111", PolicySetSourceHash: sourceHash(source), DeploymentIdentity: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		PolicySet:           EffectivePolicySet{PolicySetVersionID: "22222222-2222-4222-8222-222222222222", Source: source, SourceHash: sourceHash(source), StaticPolicyCount: 1},
		EvaluationPrincipal: EvaluationPrincipal{EntityType: "Kontext::User", EntityID: "user-1"},
		ValidFrom:           now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	identity, err := bundle.ComputeDeploymentIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bundle.DeploymentIdentity = identity
	return bundle
}
