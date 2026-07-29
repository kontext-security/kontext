package riskclassifier

import "testing"

func TestLLMGateDefaultsEnabled(t *testing.T) {
	// The flag exists to turn the LLM off; an org that never sets it must keep
	// the default behavior.
	if !NewLLMGate().Enabled() {
		t.Fatal("fresh gate should be enabled")
	}
	var nilGate *LLMGate
	if !nilGate.Enabled() {
		t.Fatal("nil gate should read as enabled")
	}
}

func TestLLMGateRemoteToggles(t *testing.T) {
	g := NewLLMGate()
	g.SetRemote(false)
	if g.Enabled() {
		t.Fatal("remote disable ignored")
	}
	g.SetRemote(true)
	if !g.Enabled() {
		t.Fatal("remote re-enable ignored")
	}
}

func TestLLMGateLocalOverrideBeatsRemote(t *testing.T) {
	// A developer who explicitly set the local mode must not be flipped by an
	// org refresh, in either direction.
	off := NewLLMGate()
	off.PinLocal(false)
	off.SetRemote(true)
	if off.Enabled() {
		t.Error("remote enable overrode a local off")
	}

	on := NewLLMGate()
	on.PinLocal(true)
	on.SetRemote(false)
	if !on.Enabled() {
		t.Error("remote disable overrode a local on")
	}
}

// TestResolveLLMEnabledHonoursPersistedDisable pins both halves of the rule:
// absence never disables (a transient fetch failure must not silently kill the
// classifier), and an explicit disable is honoured regardless of confirmation
// state (a kill switch must survive the degraded state it exists for).
func TestResolveLLMEnabledHonoursPersistedDisable(t *testing.T) {
	yes, no := true, false
	cases := []struct {
		name      string
		directive *bool
		want      bool
	}{
		{"no directive configured", nil, true},
		{"org disabled it", &no, false},
		{"org enabled it", &yes, true},
	}
	for _, tc := range cases {
		if got := ResolveLLMEnabled(tc.directive); got != tc.want {
			t.Errorf("%s: ResolveLLMEnabled = %v, want %v", tc.name, got, tc.want)
		}
	}
}
