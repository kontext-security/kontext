package managedobserve

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/managedstream"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// Every status in ADR-0012's list comes from one observation, and the
// read-back decides: a pass that wrote but can't read its entries back has
// not restored them.
func TestClaudeHookStatus(t *testing.T) {
	for _, test := range []struct {
		name string
		o    claudeHookObservation
		want string
	}{
		{"already there", claudeHookObservation{selfServe: true, before: true, after: true}, managedstream.HookInPlace},
		{"written and read back", claudeHookObservation{selfServe: true, after: true, pass: agentPass{attempted: true}}, managedstream.HookRestored},
		{"written, not read back", claudeHookObservation{selfServe: true, pass: agentPass{attempted: true}}, managedstream.HookUnrestorable},
		{"write failed", claudeHookObservation{selfServe: true, pass: agentPass{attempted: true, err: errors.New("disk full")}}, managedstream.HookUnrestorable},
		{"not this binary's to write", claudeHookObservation{selfServe: true}, managedstream.HookMissing},
		{"a file Kontext can't merge into", claudeHookObservation{selfServe: true, foreign: true, pass: agentPass{attempted: true, err: errors.New("hooks must be a JSON object")}}, managedstream.HookNotOurs},
		{"a privacy-guarded file", claudeHookObservation{selfServe: true, pass: agentPass{guarded: true}}, managedstream.HookNotOurs},
		{"local opt-out", claudeHookObservation{selfServe: true, optOut: true}, managedstream.HookAdminOff},
		{"opt-out wins even when in place", claudeHookObservation{selfServe: true, optOut: true, before: true, after: true}, managedstream.HookAdminOff},
		{"package drop-in in place", claudeHookObservation{before: true, after: true}, managedstream.HookInPlace},
		{"package drop-in gone", claudeHookObservation{}, managedstream.HookNeedsPrivileged},
		{"package drop-in back after a push", claudeHookObservation{after: true}, managedstream.HookRestored},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := claudeHookStatus(test.o); got != test.want {
				t.Fatalf("status = %s, want %s", got, test.want)
			}
		})
	}
}

// A report goes only after an admin acted, once per distinct finding, and a
// newer one queued while the older is in flight stays pending.
func TestHookReconcilerQueuesOnlyNewFindings(t *testing.T) {
	state := endpointconfig.UnmanagedHookState
	reconciler := newHookReconciler(func() endpointconfig.HookState { return state })
	clock := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	reconciler.now = func() time.Time { return clock }
	restored := []managedstream.HookActionResult{{Agent: "claude_code", ScopeKind: "user", Status: managedstream.HookRestored}}
	inPlace := []managedstream.HookActionResult{{Agent: "claude_code", ScopeKind: "user", Status: managedstream.HookInPlace}}

	if reconciler.active() {
		t.Fatal("active before any admin acted")
	}
	reconciler.record(restored)
	if report, _ := reconciler.take(); report != nil {
		t.Fatalf("queued %+v at generation 0", report)
	}

	nonce := "AAAAAAAAAAAAAAAAAAAAAA"
	state = endpointconfig.HookState{Desired: endpointconfig.HookStateInstalled, Generation: 2, RepairNonce: &nonce}
	if !reconciler.active() {
		t.Fatal("inactive after an admin acted")
	}
	reconciler.record(restored)
	report, sent := reconciler.take()
	if report == nil || report.Generation != 2 || report.Desired != "installed" || *report.RepairNonce != nonce ||
		report.FinishedAt != "2026-11-23T10:00:00Z" || report.Schema != managedstream.HookActionsSchema {
		t.Fatalf("report = %+v", report)
	}
	// The next pass finds the same: nothing new to send.
	clock = clock.Add(time.Minute)
	reconciler.record(restored)
	if again, _ := reconciler.take(); again != report {
		t.Fatal("the same finding was queued again")
	}
	// A different finding while the first is in flight: the first's
	// acknowledgement leaves the new one pending.
	reconciler.record(inPlace)
	sent()
	next, nextSent := reconciler.take()
	if next == nil || next.Results[0].Status != managedstream.HookInPlace || next.FinishedAt != "2026-11-23T10:01:00Z" {
		t.Fatalf("next = %+v", next)
	}
	nextSent()
	if left, _ := reconciler.take(); left != nil {
		t.Fatalf("left %+v", left)
	}
	// A new repair asks again, with the same finding.
	other := "BBBBBBBBBBBBBBBBBBBBBB"
	state.RepairNonce, state.Generation = &other, 3
	reconciler.record(inPlace)
	if repaired, _ := reconciler.take(); repaired == nil || *repaired.RepairNonce != other || repaired.Generation != 3 {
		t.Fatalf("repair report = %+v", repaired)
	}
	// Back to no admin state: nothing stays queued.
	state = endpointconfig.UnmanagedHookState
	reconciler.record(inPlace)
	if left, _ := reconciler.take(); left != nil {
		t.Fatalf("left %+v", left)
	}
	var none *hookReconciler
	if none.active() {
		t.Fatal("a nil reconciler is active")
	}
	if report, _ := none.take(); report != nil {
		t.Fatal("a nil reconciler has a report")
	}
}

// The probe reads Claude Code's user settings back the way the installer
// validates them, and calls a file it can't merge into someone else's.
func TestClaudeHookProbeReadsTheUserSettings(t *testing.T) {
	enabled := privacyfolder.Enabled
	privacyfolder.Enabled = false
	t.Cleanup(func() { privacyfolder.Enabled = enabled })
	home := t.TempDir()
	hermetic.SetHome(t, home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	binary := hermetic.KontextBinary(t, t.TempDir())
	probe := newClaudeHookProbe(true, home, binary)
	if probe == nil || probe.path != filepath.Join(home, ".claude", "settings.json") {
		t.Fatalf("probe = %+v", probe)
	}
	if probe.complete() || probe.foreign() {
		t.Fatal("a missing file reads complete or foreign")
	}
	if err := os.MkdirAll(filepath.Dir(probe.path), 0o700); err != nil {
		t.Fatal(err)
	}
	template, err := claudemanaged.TemplateJSON(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probe.path, template, 0o600); err != nil {
		t.Fatal(err)
	}
	if !probe.complete() || probe.foreign() {
		t.Fatal("Kontext's full set reads incomplete")
	}
	// Another binary's hooks are not this daemon's.
	other := newClaudeHookProbe(true, home, hermetic.KontextBinary(t, t.TempDir()))
	if other.complete() {
		t.Fatal("hooks naming another binary read complete")
	}
	for _, content := range []string{"{not json", "[]", "null"} {
		if err := os.WriteFile(probe.path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if probe.complete() || !probe.foreign() {
			t.Fatalf("%q: complete=%v foreign=%v", content, probe.complete(), probe.foreign())
		}
	}
	if err := os.WriteFile(probe.path, []byte(`{"hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if probe.complete() || probe.foreign() {
		t.Fatal("settings without Kontext's hooks read complete or foreign")
	}
	result := probe.action(false, healOutcome{claude: agentPass{attempted: true}})
	if result != (managedstream.HookActionResult{Agent: "claude_code", ScopeKind: "user", Status: managedstream.HookUnrestorable}) {
		t.Fatalf("action = %+v", result)
	}
}
