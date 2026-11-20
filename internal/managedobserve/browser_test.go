package managedobserve

import (
	"testing"

	"github.com/kontext-security/kontext/internal/browserevents"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func TestBrowserCaptureModeFollowsTheConfirmedDirectiveOnly(t *testing.T) {
	on, off := true, false
	confirmed := func(mode payloadcapture.Mode, workType *bool) endpointconfig.Snapshot {
		cfg := endpointconfig.Config{PayloadCaptureMode: mode, WorkTypeClassification: workType, ToolOutputCompaction: &off}
		return endpointconfig.Snapshot{Config: cfg, Configured: cfg, Confirmed: true, ConfigIdentity: "abc"}
	}
	for name, tc := range map[string]struct {
		snapshot endpointconfig.Snapshot
		want     string
	}{
		"nothing confirmed": {endpointconfig.Snapshot{}, browserevents.CaptureCommands},
		"commands":          {confirmed(payloadcapture.ModeSummary, &off), browserevents.CaptureCommands},
		"full":              {confirmed(payloadcapture.ModeFull, &off), browserevents.CaptureFull},
		"prompts":           {confirmed(payloadcapture.ModeFull, &on), browserevents.CapturePrompts},
	} {
		if got := browserCaptureMode(tc.snapshot); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}
