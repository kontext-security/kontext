package managedobserve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
)

const remoteEnforceTestPolicy = `@id("permit-read")
permit (
  principal,
  action == Kontext::Action::"ToolUse",
  resource == Kontext::Tool::"unknown"
);`

const remoteEnforceTestSchema = `namespace Kontext {
  entity Endpoint;
  entity Agent;
  entity Tool;
  action "ToolUse" appliesTo {
    principal: [Endpoint],
    resource: [Tool],
    context: {}
  };
}`

const remoteEnforceTestCatalogDigest = "cf87ee7a167f1f07bdc41450467708f832c9d8c4aaf20651a5d0df070d3de436"

// remoteEnforceTestDeployment mirrors the daemon-side deployment shape so the
// cache write below goes through the exact production persistence path.
func remoteEnforceTestDeployment(t *testing.T, mode cedareval.RolloutMode) cedarpolicy.Deployment {
	t.Helper()
	principal := cedareval.EvaluationPrincipal{
		EntityType: cedareval.EndpointEntityTypeV2,
		EntityID:   "ins_12345678901234567890123456789012",
	}
	policyHash := cedareval.ComputePolicyHash(remoteEnforceTestPolicy)
	schemaHash := cedareval.ComputeSchemaHash(remoteEnforceTestSchema)
	identity, err := cedareval.ComputeDeploymentIdentityV2(cedareval.DeploymentIdentityV2Input{
		ResponseVersion:        cedarpolicy.ResponseVersion,
		RequestContractVersion: cedarpolicy.RequestContractVersion,
		PolicySetSourceHash:    policyHash,
		SchemaHash:             schemaHash,
		ToolCatalogDigest:      remoteEnforceTestCatalogDigest,
		RolloutMode:            string(mode),
		EvaluationPrincipal:    principal,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cedarpolicy.Deployment{
		ResponseVersion:        cedarpolicy.ResponseVersion,
		RequestContractVersion: cedarpolicy.RequestContractVersion,
		PolicySet:              cedarpolicy.PolicySet{Source: remoteEnforceTestPolicy, SourceHash: policyHash},
		Schema:                 cedarpolicy.Schema{Source: remoteEnforceTestSchema, Hash: schemaHash},
		ToolCatalogDigest:      remoteEnforceTestCatalogDigest,
		RolloutMode:            mode,
		EvaluationPrincipal:    principal,
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

	t.Run("version one enforce cache keeps its claim", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "guard.db")
		t.Setenv("KONTEXT_MANAGED_OBSERVE_DB", dbPath)
		path := cedarpolicy.DefaultCachePathForDB(DefaultDBPath())
		if err := os.WriteFile(path, []byte(`{"version":1,"state":"success","deployment":{"rolloutMode":"enforce"}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if !remoteEnforceFromCache() {
			t.Fatal("remoteEnforceFromCache() = false, want enforcement claim from version one cache")
		}
	})

	t.Run("old catalog digest keeps its enforce claim", func(t *testing.T) {
		writeCache(t, cedareval.RolloutModeEnforce)
		path := cedarpolicy.DefaultCachePathForDB(DefaultDBPath())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data = []byte(strings.Replace(string(data), remoteEnforceTestCatalogDigest, strings.Repeat("0", 64), 1))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if !remoteEnforceFromCache() {
			t.Fatal("remoteEnforceFromCache() = false, want enforcement claim from previous catalog cache")
		}
	})
}
