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
	if got := captureConfiguration(cache.Current(), ""); got.WorkTypeClassification || got.Confirmed {
		t.Fatalf("unconfirmed configuration enables the switch: %+v", got)
	}
	on, off := true, false
	config := endpointconfig.Config{PayloadCaptureMode: payloadcapture.ModeFull, WorkTypeClassification: &on, ToolOutputCompaction: &off, CodexProxy: &on, HookInventory: &off}
	identity, err := endpointconfig.ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	response := endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: config, ConfigIdentity: identity}
	if err := cache.Apply(endpointconfig.FetchResult{Response: &response, ETag: identity}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got := captureConfiguration(cache.Current(), "")
	if !got.WorkTypeClassification || got.EffectiveMode != payloadcapture.ModeFull || !got.Confirmed {
		t.Fatalf("confirmed directive not applied: %+v", got)
	}
	// A failed refresh retains the last validated directive.
	cache.MarkFailed(nil, time.Now().UTC())
	if got := captureConfiguration(cache.Current(), ""); !got.WorkTypeClassification || got.EffectiveMode != payloadcapture.ModeFull || !got.Confirmed {
		t.Fatalf("failed refresh lost the switch: %+v", got)
	}
}

// Another enrolment's confirmed directive, the previous workspace's after a
// re-enrolment on the same cloud, holds prompts as opted out.
func TestCaptureConfigurationBelongsToItsEnrolment(t *testing.T) {
	cache := endpointconfig.NewCache(filepath.Join(t.TempDir(), "endpoint-config.json"))
	cache.Bind("https://cloud.example", "token-a")
	on, off := true, false
	config := endpointconfig.Config{PayloadCaptureMode: payloadcapture.ModeFull, WorkTypeClassification: &on, ToolOutputCompaction: &off, CodexProxy: &on, HookInventory: &off}
	identity, err := endpointconfig.ComputeIdentity(config)
	if err != nil {
		t.Fatal(err)
	}
	response := endpointconfig.Response{ResponseVersion: endpointconfig.ResponseVersion, Config: config, ConfigIdentity: identity}
	if err := cache.Apply(endpointconfig.FetchResult{Response: &response, ETag: identity}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if got := captureConfiguration(cache.Current(), endpointconfig.Owner("token-a")); !got.Confirmed || !got.WorkTypeClassification {
		t.Fatalf("own enrolment: %+v", got)
	}
	if got := captureConfiguration(cache.Current(), endpointconfig.Owner("token-b")); got.Confirmed || got.WorkTypeClassification || !got.PromptVeto {
		t.Fatalf("other enrolment: %+v", got)
	}
	// Once the config names another cloud, nothing here owns the directive.
	if got := captureConfiguration(cache.Current(), ownerAtAnotherCloud); got.Confirmed || !got.PromptVeto {
		t.Fatalf("another cloud: %+v", got)
	}
}

// The enrolment follows the token the config holds, and says when it moves.
func TestLiveEnrolmentFollowsTheToken(t *testing.T) {
	moves := 0
	live := &liveEnrolment{owner: "a", onChange: func() { moves++ }}
	live.set("a")
	live.set("")
	live.set("b")
	if live.get() != "b" || moves != 1 {
		t.Fatalf("%q %d", live.get(), moves)
	}
}
