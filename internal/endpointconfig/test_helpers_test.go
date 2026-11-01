package endpointconfig

import (
	"testing"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func testResponse(t *testing.T, mode payloadcapture.Mode) Response {
	t.Helper()
	// The server always emits both switches under v4, defaulting work-type
	// classification on and tool output compaction off, so that is what a
	// representative response looks like.
	enabled, compaction := true, false
	config := Config{PayloadCaptureMode: mode, WorkTypeClassification: &enabled, ToolOutputCompaction: &compaction}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}
