package endpointconfig

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// A confirmed v7 hook state survives a restart, and nothing less than a
// confirmed config moves a Mac off unmanaged.
func TestHookStateIsTheConfirmedConfigs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint-config.json")
	cache := NewCache(path)
	if got := cache.Current().HookState(); got != UnmanagedHookState {
		t.Fatalf("no config: %+v", got)
	}
	response := testResponse(t, payloadcapture.ModeSummary)
	nonce := "Zm9vYmFyYmF6cXV4cXV1eDEy"
	state := HookState{Desired: HookStateInstalled, Generation: 7, RepairNonce: &nonce}
	response.Config.HookState = &state
	identity, err := ComputeIdentity(response.Config)
	if err != nil {
		t.Fatal(err)
	}
	response.ConfigIdentity = identity
	if err := cache.Apply(FetchResult{Response: &response}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	got := cache.Current().HookState()
	if got.Desired != HookStateInstalled || got.Generation != 7 || got.Nonce() != nonce {
		t.Fatalf("confirmed: %+v", got)
	}
	restarted := NewCache(path)
	if err := restarted.Load(); err != nil {
		t.Fatal(err)
	}
	if got := restarted.Current().HookState(); got.Desired != HookStateInstalled || got.Generation != 7 || got.Nonce() != nonce {
		t.Fatalf("after restart: %+v", got)
	}
	// Every field is in the identity: a changed one is a new config.
	for name, change := range map[string]func(*HookState){
		"desired":    func(h *HookState) { h.Desired = HookStateUnmanaged },
		"generation": func(h *HookState) { h.Generation++ },
		"nonce":      func(h *HookState) { h.RepairNonce = nil },
	} {
		changed := state
		change(&changed)
		config := response.Config
		config.HookState = &changed
		other, err := ComputeIdentity(config)
		if err != nil {
			t.Fatal(err)
		}
		if other == identity {
			t.Fatalf("%s is not part of the identity", name)
		}
	}
}
