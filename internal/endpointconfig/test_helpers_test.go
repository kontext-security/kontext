package endpointconfig

import (
	"testing"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

func testResponse(t *testing.T, mode payloadcapture.Mode) Response {
	t.Helper()
	// The server always emits the guardrail flag under v2 and defaults it to
	// enabled, so that is what a representative response looks like.
	enabled := true
	config := Config{PayloadCaptureMode: mode, GuardrailLLMEnabled: &enabled}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}
