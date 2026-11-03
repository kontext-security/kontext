package endpointconfig

import (
	"testing"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func testResponse(t *testing.T, mode payloadcapture.Mode) Response {
	t.Helper()
	// The server always emits every switch under v5, defaulting work-type
	// classification and the Codex proxy on and tool output compaction off,
	// so that is what a representative response looks like.
	enabled, compaction, codexProxy := true, false, true
	config := Config{PayloadCaptureMode: mode, WorkTypeClassification: &enabled, ToolOutputCompaction: &compaction, CodexProxy: &codexProxy}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}

// fallbackResponse is what a server that predates v5 answers the fallback
// with: v4, which has no Codex proxy switch.
func fallbackResponse(t *testing.T, mode payloadcapture.Mode, compaction bool) Response {
	t.Helper()
	enabled := true
	config := Config{PayloadCaptureMode: mode, WorkTypeClassification: &enabled, ToolOutputCompaction: &compaction}
	identity, err := computeIdentity(FallbackResponseVersion, config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: FallbackResponseVersion, Config: config, ConfigIdentity: identity}
}
