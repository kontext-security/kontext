package managedobserve

import (
	"github.com/kontext-security/kontext/internal/browserevents"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// browserCaptureMode is the Data collection step the browser extension is
// told, from the same confirmed directive as hook capture: anything not
// confirmed reads as Commands, the most restrictive.
func browserCaptureMode(snapshot endpointconfig.Snapshot) string {
	capture := captureConfiguration(snapshot)
	if !capture.Confirmed || capture.EffectiveMode != payloadcapture.ModeFull {
		return browserevents.CaptureCommands
	}
	if capture.WorkTypeClassification {
		return browserevents.CapturePrompts
	}
	return browserevents.CaptureFull
}
