package managedobserve

import (
	"github.com/kontext-security/kontext/internal/browserevents"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// browserCaptureMode is the Data collection step the browser extension is
// told, from the same confirmed directive as hook capture: anything not
// confirmed, or confirmed for an enrollment other than the one the config
// names now, reads as Commands, the most restrictive.
func browserCaptureMode(snapshot endpointconfig.Snapshot, owner string) string {
	capture := captureConfiguration(snapshot, owner)
	if !capture.Confirmed || capture.EffectiveMode != payloadcapture.ModeFull {
		return browserevents.CaptureCommands
	}
	if capture.WorkTypeClassification {
		return browserevents.CapturePrompts
	}
	return browserevents.CaptureFull
}
