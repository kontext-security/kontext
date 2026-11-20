package managedobserve

import (
	"context"
	"testing"

	"github.com/kontext-security/kontext/internal/agentinventory"
	"github.com/kontext-security/kontext/pkg/agentauthority"
)

type fakeHookScan struct {
	calls    int
	recorded int
	discards int
	// confirmed is whether the switch comes from a confirmed config.
	confirmed bool
	opts      agentauthority.HookScanOptions
}

func (f *fakeHookScan) holder(on *bool, keys *hookKeyBox) *hookHolder {
	return &hookHolder{
		keys:      keys,
		enabled:   func() bool { return *on },
		confirmed: func() bool { return f.confirmed },
		home:      func() (string, error) { return "/Users/dana", nil },
		scan: func(_ context.Context, opts agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error) {
			f.calls++
			f.opts = opts
			return agentauthority.HookAgent{ID: "claude_code"}, agentauthority.SourceResult{ID: "claude_code/hooks", Status: agentauthority.StatusComplete}, nil
		},
		record:  func(agentauthority.HookAgent, agentauthority.SourceResult) { f.recorded++ },
		discard: func() { f.discards++ },
	}
}

// Nothing is read while the switch is off or the key is unknown; once on, a
// scan is recorded with the key and the agent's version; turning it off
// discards the pending results once. A confirmed config that says off drops
// results a previous run stored, even on the first tick.
func TestHookHolderFollowsSwitchAndKey(t *testing.T) {
	fake := &fakeHookScan{}
	on := false
	keys := newHookKeyBox()
	h := fake.holder(&on, keys)
	version := "2.1.329"
	inv := agentinventory.Inventory{Agents: []agentinventory.Agent{{ID: "claude_code", Version: &version}}}

	h.refresh(context.Background(), inv)
	if fake.calls != 0 || fake.discards != 0 {
		t.Fatalf("unconfirmed off: %+v", fake)
	}
	fake.confirmed = true
	h.refresh(context.Background(), inv)
	h.refresh(context.Background(), inv)
	if fake.calls != 0 || fake.discards != 1 {
		t.Fatalf("confirmed off at start: %+v", fake)
	}
	fake.discards = 0
	on = true
	h.refresh(context.Background(), inv)
	if fake.calls != 0 {
		t.Fatal("scanned without K_dev")
	}
	keys.set([]byte("k"))
	h.refresh(context.Background(), inv)
	if fake.calls != 1 || fake.recorded != 1 || string(fake.opts.Key) != "k" || fake.opts.AgentVersion != version || fake.opts.Home != "/Users/dana" {
		t.Fatalf("switch on: %+v", fake)
	}
	on = false
	h.refresh(context.Background(), inv)
	h.refresh(context.Background(), inv)
	if fake.discards != 1 || fake.calls != 1 {
		t.Fatalf("switch off again: %+v", fake)
	}
}

// A scan that finishes after the switch went off records nothing.
func TestHookHolderDropsAScanFinishedAfterTurnOff(t *testing.T) {
	fake := &fakeHookScan{}
	on := true
	keys := newHookKeyBox()
	keys.set([]byte("k"))
	h := fake.holder(&on, keys)
	scan := h.scan
	h.scan = func(ctx context.Context, opts agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error) {
		on = false
		return scan(ctx, opts)
	}
	h.refresh(context.Background(), agentinventory.Inventory{})
	if fake.calls != 1 || fake.recorded != 0 {
		t.Fatalf("%+v", fake)
	}
}

// A scan read under a key the workspace no longer has records nothing, and
// nothing uploads while the key is withheld.
func TestHookHolderDropsAScanUnderAnOldKey(t *testing.T) {
	fake := &fakeHookScan{}
	on := true
	keys := newHookKeyBox()
	keys.set([]byte("k"))
	h := fake.holder(&on, keys)
	scan := h.scan
	h.scan = func(ctx context.Context, opts agentauthority.HookScanOptions) (agentauthority.HookAgent, agentauthority.SourceResult, error) {
		keys.clear()
		return scan(ctx, opts)
	}
	h.refresh(context.Background(), agentinventory.Inventory{})
	if fake.calls != 1 || fake.recorded != 0 || h.uploading() {
		t.Fatalf("%+v uploading=%v", fake, h.uploading())
	}
}
