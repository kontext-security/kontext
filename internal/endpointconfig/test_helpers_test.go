package endpointconfig

import (
	"testing"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func testResponse(t *testing.T, mode payloadcapture.Mode) Response {
	t.Helper()
	// The server always emits every switch under v6, defaulting work-type
	// classification and the Codex proxy on and tool output compaction and
	// hook inventory off, so that is what a representative response looks
	// like.
	enabled, compaction, codexProxy, hookInventory := true, false, true, false
	config := Config{PayloadCaptureMode: mode, WorkTypeClassification: &enabled, ToolOutputCompaction: &compaction, CodexProxy: &codexProxy, HookInventory: &hookInventory}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}

// fallbackResponse is what a server that predates v6 answers the fallback
// with: v5, which has no hook inventory switch.
func fallbackResponse(t *testing.T, mode payloadcapture.Mode, compaction bool) Response {
	t.Helper()
	enabled, codexProxy := true, true
	config := Config{PayloadCaptureMode: mode, WorkTypeClassification: &enabled, ToolOutputCompaction: &compaction, CodexProxy: &codexProxy}
	identity, err := computeIdentity(FallbackResponseVersion, config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: FallbackResponseVersion, Config: config, ConfigIdentity: identity}
}
