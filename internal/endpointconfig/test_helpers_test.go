package endpointconfig

import (
	"testing"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func testResponse(t *testing.T, mode payloadcapture.Mode) Response {
	t.Helper()
	// The server always emits the work-type switch under v3 and defaults it to
	// on, so that is what a representative response looks like.
	enabled := true
	config := Config{PayloadCaptureMode: mode, WorkTypeClassification: &enabled}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}
