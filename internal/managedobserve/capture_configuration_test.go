package managedobserve

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// The work-type switch reaches the store with the capture mode, and only
// from a confirmed directive: until then turns carry no prompt text.
func TestCaptureConfigurationCarriesWorkTypeSwitchOnlyWhenConfirmed(t *testing.T) {
	cache := endpointconfig.NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	if got := captureConfiguration(cache.Current()); got.WorkTypeClassification || got.Confirmed {
		t.Fatalf("unconfirmed configuration enables the switch: %+v", got)
	}
	on := true
	config := endpointconfig.Config{PayloadCaptureMode: payloadcapture.ModeFull, WorkTypeClassification: &on}
	identity, err := endpointconfig.ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	response := endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: config, ConfigIdentity: identity}
	if err := cache.Apply(endpointconfig.FetchResult{Response: &response, ETag: identity}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got := captureConfiguration(cache.Current())
	if !got.WorkTypeClassification || got.EffectiveMode != payloadcapture.ModeFull || !got.Confirmed {
		t.Fatalf("confirmed directive not applied: %+v", got)
	}
	// A failed refresh degrades both together.
	cache.MarkFailed(nil, time.Now().UTC())
	if got := captureConfiguration(cache.Current()); got.WorkTypeClassification || got.EffectiveMode != payloadcapture.ModeSummary {
		t.Fatalf("failed refresh kept the switch: %+v", got)
	}
}
