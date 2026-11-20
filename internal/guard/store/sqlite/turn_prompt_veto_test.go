package sqlite

import (
	"testing"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// A prompt opt-out kept through a rollback records the prompt as omitted,
// which recovery never rehydrates, not as an unconfirmed skip.
func TestPromptVetoOmitsThePrompt(t *testing.T) {
	vetoed := payloadcapture.DefaultRuntimeConfiguration()
	vetoed.PromptVeto = true
	if got := CaptureTurnPrompt("deploy the thing", vetoed); got.Mode != TurnPromptOmitted {
		t.Fatalf("vetoed prompt mode = %q", got.Mode)
	}
	if got := CaptureTurnPrompt("deploy the thing", payloadcapture.DefaultRuntimeConfiguration()); got.Mode != TurnPromptSkipped {
		t.Fatalf("unconfirmed prompt mode = %q", got.Mode)
	}
}
