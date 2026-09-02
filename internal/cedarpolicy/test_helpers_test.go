package cedarpolicy

import (
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
)

const testPolicy = `@id("permit-read")
permit (
  principal,
  action == Kontext::Action::"ToolUse",
  resource == Kontext::Tool::"unknown"
);`

const testSchema = `namespace Kontext {
  entity Endpoint;
  entity Agent;
  entity Tool;
  action "ToolUse" appliesTo {
    principal: [Endpoint],
    resource: [Tool],
    context: {}
  };
}`

const testToolCatalogDigest = "cf87ee7a167f1f07bdc41450467708f832c9d8c4aaf20651a5d0df070d3de436"

func testDeployment(t *testing.T, mode cedareval.RolloutMode) Deployment {
	t.Helper()
	principal := cedareval.EvaluationPrincipal{
		EntityType: cedareval.EndpointEntityTypeV2,
		EntityID:   "ins_12345678901234567890123456789012",
	}
	policyHash := cedareval.ComputePolicyHash(testPolicy)
	schemaHash := cedareval.ComputeSchemaHash(testSchema)
	identity, err := cedareval.ComputeDeploymentIdentityV2(cedareval.DeploymentIdentityV2Input{
		ResponseVersion:        ResponseVersion,
		RequestContractVersion: RequestContractVersion,
		PolicySetSourceHash:    policyHash,
		SchemaHash:             schemaHash,
		ToolCatalogDigest:      testToolCatalogDigest,
		RolloutMode:            string(mode),
		EvaluationPrincipal:    principal,
	})
	if err != nil {
		t.Fatal(err)
	}
	return Deployment{
		ResponseVersion:        ResponseVersion,
		RequestContractVersion: RequestContractVersion,
		PolicySet:              PolicySet{Source: testPolicy, SourceHash: policyHash},
		Schema:                 Schema{Source: testSchema, Hash: schemaHash},
		ToolCatalogDigest:      testToolCatalogDigest,
		RolloutMode:            mode,
		EvaluationPrincipal:    principal,
		DeploymentIdentity:     identity,
	}
}

// testDeploymentIdentity recomputes the identity after a test mutates a
// deployment's metadata (for example its tool catalog digest).
func testDeploymentIdentity(t *testing.T, d Deployment) string {
	t.Helper()
	identity, err := cedareval.ComputeDeploymentIdentityV2(cedareval.DeploymentIdentityV2Input{
		ResponseVersion:        d.ResponseVersion,
		RequestContractVersion: d.RequestContractVersion,
		PolicySetSourceHash:    d.PolicySet.SourceHash,
		SchemaHash:             d.Schema.Hash,
		ToolCatalogDigest:      d.ToolCatalogDigest,
		RolloutMode:            string(d.RolloutMode),
		EvaluationPrincipal:    d.EvaluationPrincipal,
	})
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func testLegacyDeployment(t *testing.T, mode cedareval.RolloutMode) LegacyDeployment {
	t.Helper()
	policy := `@id("permit") permit(principal, action, resource);`
	principal := cedareval.EvaluationPrincipal{EntityType: cedareval.PrincipalEntityType, EntityID: "ins_12345678901234567890123456789012"}
	policyHash := cedareval.ComputePolicyHash(policy)
	identity, err := cedareval.ComputeDeploymentIdentity(cedareval.DeploymentIdentityInput{
		ResponseVersion:        1,
		RequestContractVersion: 1,
		PolicyHash:             policyHash,
		RolloutMode:            string(mode),
		EvaluationPrincipal:    principal,
	})
	if err != nil {
		t.Fatal(err)
	}
	return LegacyDeployment{
		ResponseVersion:        1,
		RequestContractVersion: 1,
		PolicyHash:             policyHash,
		RolloutMode:            mode,
		EvaluationPrincipal:    principal,
		PolicyText:             policy,
		DeploymentIdentity:     identity,
	}
}
