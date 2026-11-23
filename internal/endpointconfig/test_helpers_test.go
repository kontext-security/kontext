package endpointconfig

import (
	"testing"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func testResponse(t *testing.T, mode payloadcapture.Mode) Response {
	t.Helper()
	// The server always emits every switch under v7, defaulting work-type
	// classification and the Codex proxy on, tool output compaction and
	// hook inventory off and the hooks unmanaged, so that is what a
	// representative response looks like.
	enabled, compaction, codexProxy, hookInventory := true, false, true, false
	hookState := UnmanagedHookState
	config := Config{PayloadCaptureMode: mode, WorkTypeClassification: &enabled, ToolOutputCompaction: &compaction, CodexProxy: &codexProxy, HookInventory: &hookInventory, HookState: &hookState}
	identity, err := ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: ResponseVersion, Config: config, ConfigIdentity: identity}
}

// fallbackResponse is what a server that predates v7 answers the fallback
// with: v6, which has no desired hook state. Its hook inventory switch is on,
// so a test can tell the fallback's switches apart from the defaults.
func fallbackResponse(t *testing.T, mode payloadcapture.Mode, compaction bool) Response {
	t.Helper()
	enabled, codexProxy, hookInventory := true, true, true
	config := Config{PayloadCaptureMode: mode, WorkTypeClassification: &enabled, ToolOutputCompaction: &compaction, CodexProxy: &codexProxy, HookInventory: &hookInventory}
	identity, err := computeIdentity(FallbackResponseVersion, config)
	if err != nil {
		t.Fatal(err)
	}
	return Response{ResponseVersion: FallbackResponseVersion, Config: config, ConfigIdentity: identity}
}
