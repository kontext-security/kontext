package endpointconfig

import (
	"testing"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

func testResponse(t *testing.T, mode payloadcapture.Mode) Response {
	t.Helper()
	// The server always emits both runtime directives under v3.
	enabled := true
	disabled := false
	config := Config{PayloadCaptureMode: mode, GuardrailLLMEnabled: &enabled, PromptPolicyEnabled: &disabled}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}
