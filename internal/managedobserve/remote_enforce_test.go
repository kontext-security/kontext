package managedobserve

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
)

const remoteEnforceTestPolicy = `@id("permit-read")
permit (
  principal,
  action == Kontext::Action::"ToolUse",
  resource == Kontext::Tool::"Read"
);`

// remoteEnforceTestDeployment mirrors the daemon-side deployment shape so the
// cache write below goes through the exact production persistence path.
func remoteEnforceTestDeployment(t *testing.T, mode cedareval.RolloutMode) cedarpolicy.Deployment {
	t.Helper()
	principal := cedareval.EvaluationPrincipal{
		EntityType: cedareval.PrincipalEntityType,
		EntityID:   "user@example.com",
	}
	policyHash := cedareval.ComputePolicyHash(remoteEnforceTestPolicy)
	identity, err := cedareval.ComputeDeploymentIdentity(cedareval.DeploymentIdentityInput{
		ResponseVersion:        cedarpolicy.ResponseVersion,
		RequestContractVersion: cedarpolicy.RequestContractVersion,
		PolicyHash:             policyHash,
		RolloutMode:            string(mode),
		EvaluationPrincipal:    principal,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cedarpolicy.Deployment{
		ResponseVersion:        cedarpolicy.ResponseVersion,
		RequestContractVersion: cedarpolicy.RequestContractVersion,
		PolicyHash:             policyHash,
		RolloutMode:            mode,
		EvaluationPrincipal:    principal,
		PolicyText:             remoteEnforceTestPolicy,
		DeploymentIdentity:     identity,
	}
}

// TestRemoteEnforceFromCacheRoundTrip pins the cross-process file contract:
// the hook's outage fallback must read the enforcement claim from a cache
// file the daemon wrote. A cedarpolicy cache-format change that breaks this
// silently turns remote-mode outages fail-open; this test makes it loud.
func TestRemoteEnforceFromCacheRoundTrip(t *testing.T) {
	writeCache := func(t *testing.T, mode cedareval.RolloutMode) {
		t.Helper()
		dbPath := filepath.Join(t.TempDir(), "guard.db")
		t.Setenv("KONTEXT_MANAGED_OBSERVE_DB", dbPath)
		deployment := remoteEnforceTestDeployment(t, mode)
		cache := cedarpolicy.NewCache(cedarpolicy.DefaultCachePathForDB(DefaultDBPath()), time.Hour)
		if err := cache.Apply(cedarpolicy.FetchResult{
			State:      cedarpolicy.StateSuccess,
			Deployment: &deployment,
			ETag:       deployment.DeploymentIdentity,
		}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("enforce deployment claims enforcement", func(t *testing.T) {
		writeCache(t, cedareval.RolloutModeEnforce)
		if !remoteEnforceFromCache() {
			t.Fatal("remoteEnforceFromCache() = false, want enforcement claim from daemon-written cache")
		}
	})

	t.Run("observe deployment claims nothing", func(t *testing.T) {
		writeCache(t, cedareval.RolloutModeObserve)
		if remoteEnforceFromCache() {
			t.Fatal("remoteEnforceFromCache() = true, want no enforcement claim for observe deployment")
		}
	})

	t.Run("missing cache fails open", func(t *testing.T) {
		t.Setenv("KONTEXT_MANAGED_OBSERVE_DB", filepath.Join(t.TempDir(), "guard.db"))
		if remoteEnforceFromCache() {
			t.Fatal("remoteEnforceFromCache() = true, want no claim without a cache")
		}
	})
}
