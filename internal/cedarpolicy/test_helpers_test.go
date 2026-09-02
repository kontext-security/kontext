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

const testToolCatalogDigest = "f86247e4b2a3f0121a482c1ba9cc8f6913e4d22f73478b66237bbdbe5ff26b92"

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
