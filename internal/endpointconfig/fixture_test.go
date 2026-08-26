package endpointconfig

import (
	"encoding/json"
	"testing"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// This vector is mirrored by the TypeScript contract test. Keeping one small
// explicit vector is easier to audit than a generated Cartesian-product file.
func TestPortableV3IdentityVector(t *testing.T) {
	enabled := true
	config := Config{
		PayloadCaptureMode:  payloadcapture.ModeSummary,
		GuardrailLLMEnabled: &enabled,
		PromptPolicyEnabled: &enabled,
	}
	preimage, err := json.Marshal([]any{
		identityDomain,
		ResponseVersion,
		string(config.PayloadCaptureMode),
		*config.GuardrailLLMEnabled,
		*config.PromptPolicyEnabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	const expectedPreimage = `["kontext:endpoint-config:v3",3,"summary",true,true]`
	if string(preimage) != expectedPreimage {
		t.Fatalf("preimage = %s, want %s", preimage, expectedPreimage)
	}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	const expectedIdentity = "445d27e4721a7c9ae886574397074813678e540c7924be75c44a58eb465e264f"
	if identity != expectedIdentity {
		t.Fatalf("identity = %s, want %s", identity, expectedIdentity)
	}
}
