package cedarpolicy

import (
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
)

const testPolicy = `@id("permit-read")
permit (
  principal,
  action == Kontext::Action::"ToolUse",
  resource == Kontext::Tool::"Read"
);`

func testDeployment(t *testing.T, mode cedareval.RolloutMode) Deployment {
	t.Helper()
	principal := cedareval.EvaluationPrincipal{
		EntityType: cedareval.PrincipalEntityType,
		EntityID:   "user@example.com",
	}
	policyHash := cedareval.ComputePolicyHash(testPolicy)
	identity, err := cedareval.ComputeDeploymentIdentity(cedareval.DeploymentIdentityInput{
		ResponseVersion:        ResponseVersion,
		RequestContractVersion: RequestContractVersion,
		PolicyHash:             policyHash,
		RolloutMode:            string(mode),
		EvaluationPrincipal:    principal,
	})
	if err != nil {
		t.Fatal(err)
	}
	return Deployment{
		ResponseVersion:        ResponseVersion,
		RequestContractVersion: RequestContractVersion,
		PolicyHash:             policyHash,
		RolloutMode:            mode,
		EvaluationPrincipal:    principal,
		PolicyText:             testPolicy,
		DeploymentIdentity:     identity,
	}
}
