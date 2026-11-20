package managedobserve

import (
	"context"
	"path/filepath"
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
	tag       string
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
		record:  func(_ agentauthority.HookAgent, _ agentauthority.SourceResult, tag string) { f.recorded++; f.tag = tag },
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
	keys.set([]byte("k"), "t")
	h.refresh(context.Background(), inv)
	if fake.tag == "" || fake.tag != hookKeyTag([]byte("k")) || fake.tag == hookKeyTag([]byte("k2")) {
		t.Fatalf("key tag %q", fake.tag)
	}
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
	keys.set([]byte("k"), "t")
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
	keys.set([]byte("k"), "t")
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

// A confirmed off drops stored results at start even when no key can be
// derived: run checks the switch before it waits for the key.
func TestHookHolderRunDiscardsBeforeTheKey(t *testing.T) {
	fake := &fakeHookScan{confirmed: true}
	on := false
	h := fake.holder(&on, newHookKeyBox())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.run(ctx, &agentInventoryHolder{})
	if fake.discards != 1 || fake.calls != 0 {
		t.Fatalf("%+v", fake)
	}
}

// After a re-enrolment the cache still holds the previous workspace's opt-in
// until the new workspace's settings arrive: nothing is scanned or sent under
// the new key until then.
func TestHookHolderWaitsForTheNewEnrolmentsSettings(t *testing.T) {
	fake := &fakeHookScan{confirmed: true}
	on := true
	keys := newHookKeyBox()
	gate := &enrolmentGate{}
	gate.set("token-a")
	keys.set([]byte("k-b"), "token-b")
	h := fake.holder(&on, keys)
	h.authorized = func() bool { return gate.matches(keys.enrolment()) }
	h.refresh(context.Background(), agentinventory.Inventory{})
	if fake.calls != 0 || h.uploading() {
		t.Fatalf("scanned under A's opt-in: %+v uploading=%v", fake, h.uploading())
	}
	gate.set("token-b")
	h.refresh(context.Background(), agentinventory.Inventory{})
	if fake.calls != 1 || fake.recorded != 1 || !h.uploading() {
		t.Fatalf("B's settings arrived: %+v", fake)
	}
}

func TestHookSwitchWatchWakesOnChangesOnly(t *testing.T) {
	var w hookSwitchWatch
	steps := []struct {
		on, confirmed, want bool
	}{{false, true, true}, {false, true, false}, {false, true, false}, {true, true, true}, {true, true, false}}
	for i, step := range steps {
		if got := w.config(step.on, step.confirmed); got != step.want {
			t.Fatalf("step %d: woke=%v", i, got)
		}
	}
	if !w.enrolment("a") || w.enrolment("a") || !w.enrolment("b") {
		t.Fatal("enrolment changes")
	}
}

func TestClaudeConfigDirFollowsTheEnvironment(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "relative/dir")
	if got := ClaudeConfigDir(); got != "" {
		t.Fatalf("relative dir used: %q", got)
	}
	dir := t.TempDir()
	t.Setenv("CLAUDE_CONFIG_DIR", dir+"/")
	if got := ClaudeConfigDir(); got != filepath.Clean(dir) {
		t.Fatalf("got %q", got)
	}
}
