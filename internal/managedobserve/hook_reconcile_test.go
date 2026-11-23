package managedobserve

import (
	"encoding/json"
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
	state, owner := endpointconfig.UnmanagedHookState, "owner-a"
	reconciler := newHookReconciler(func() (endpointconfig.HookState, string) { return state, owner })
	clock := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	reconciler.now = func() time.Time { return clock }
	result := func(status string) []managedstream.HookActionResult {
		return []managedstream.HookActionResult{{Agent: "claude_code", ScopeKind: "user", Status: status}}
	}
	// record runs one pass that starts and finishes under the current state.
	record := func(status string) {
		pass, _ := reconciler.begin()
		reconciler.record(pass, result(status))
	}

	if _, reporting := reconciler.begin(); reporting {
		t.Fatal("reporting before any admin acted")
	}
	record(managedstream.HookRestored)
	if report, _ := reconciler.take(owner); report != nil {
		t.Fatalf("queued %+v at generation 0", report)
	}

	nonce := "AAAAAAAAAAAAAAAAAAAAAA"
	state = endpointconfig.HookState{Desired: endpointconfig.HookStateInstalled, Generation: 2, RepairNonce: &nonce}
	if _, reporting := reconciler.begin(); !reporting {
		t.Fatal("not reporting after an admin acted")
	}
	record(managedstream.HookRestored)
	report, sent := reconciler.take(owner)
	if report == nil || report.Generation != 2 || report.Desired != "installed" || *report.RepairNonce != nonce ||
		report.FinishedAt != "2026-11-23T10:00:00Z" || report.Schema != managedstream.HookActionsSchema {
		t.Fatalf("report = %+v", report)
	}
	// The next pass finds the same: nothing new to send.
	clock = clock.Add(time.Minute)
	record(managedstream.HookRestored)
	if again, _ := reconciler.take(owner); again != report {
		t.Fatal("the same finding was queued again")
	}
	// The repaired hooks found in place before the repair went up: the
	// cloud still hears "restored".
	record(managedstream.HookInPlace)
	if kept, _ := reconciler.take(owner); kept != report {
		t.Fatalf("a periodic pass replaced the unsent repair: %+v", kept)
	}
	// A different finding while the first is in flight: the first's
	// acknowledgement leaves the new one pending.
	record(managedstream.HookMissing)
	sent()
	next, nextSent := reconciler.take(owner)
	if next == nil || next.Results[0].Status != managedstream.HookMissing || next.FinishedAt != "2026-11-23T10:01:00Z" {
		t.Fatalf("next = %+v", next)
	}
	nextSent()
	if left, _ := reconciler.take(owner); left != nil {
		t.Fatalf("left %+v", left)
	}
	// A new repair asks again, with the same finding.
	other := "BBBBBBBBBBBBBBBBBBBBBB"
	state.RepairNonce, state.Generation = &other, 3
	record(managedstream.HookMissing)
	if repaired, _ := reconciler.take(owner); repaired == nil || *repaired.RepairNonce != other || repaired.Generation != 3 {
		t.Fatalf("repair report = %+v", repaired)
	}
	// Back to no admin state: nothing stays queued.
	state = endpointconfig.UnmanagedHookState
	record(managedstream.HookInPlace)
	if left, _ := reconciler.take(owner); left != nil {
		t.Fatalf("left %+v", left)
	}
	var none *hookReconciler
	if _, reporting := none.begin(); reporting {
		t.Fatal("a nil reconciler reports")
	}
	if report, _ := none.take(""); report != nil {
		t.Fatal("a nil reconciler has a report")
	}
}

// A queued report goes only with the enrolment and the request it was made
// for: a re-enrolment, a fallback to v6 or a pass that started under an
// older request sends nothing.
func TestHookReconcilerSendsOnlyForItsRequest(t *testing.T) {
	nonce := "AAAAAAAAAAAAAAAAAAAAAA"
	installed := endpointconfig.HookState{Desired: endpointconfig.HookStateInstalled, Generation: 1, RepairNonce: &nonce}
	state, owner := installed, "owner-a"
	reconciler := newHookReconciler(func() (endpointconfig.HookState, string) { return state, owner })
	restored := []managedstream.HookActionResult{{Agent: "claude_code", ScopeKind: "user", Status: managedstream.HookRestored}}
	queue := func() {
		t.Helper()
		pass, _ := reconciler.begin()
		reconciler.record(pass, restored)
	}

	// Re-enrolled in another workspace with the same generation.
	queue()
	owner = "owner-b"
	if report, _ := reconciler.take(owner); report != nil {
		t.Fatalf("workspace A's report went with B's token: %+v", report)
	}
	// A post goes with another token than the config's (a flush that began
	// before a re-enrolment): it carries nothing, and the report waits for
	// a post with its own enrolment's token.
	owner = "owner-a"
	queue()
	if report, _ := reconciler.take("owner-b"); report != nil {
		t.Fatalf("workspace A's report went with B's token: %+v", report)
	}
	if report, _ := reconciler.take(owner); report == nil {
		t.Fatal("a post with another token dropped the report")
	}
	// The cloud rolled back to v6: unmanaged, nothing goes.
	owner = "owner-a"
	queue()
	state = endpointconfig.UnmanagedHookState
	if report, _ := reconciler.take(owner); report != nil {
		t.Fatalf("a report went to a v6 cloud: %+v", report)
	}
	// Generation 2 arrived while a generation 1 pass ran: that pass
	// reports nothing, and the next one reports generation 2.
	state = installed
	pass, _ := reconciler.begin()
	second := "BBBBBBBBBBBBBBBBBBBBBB"
	state = endpointconfig.HookState{Desired: endpointconfig.HookStateInstalled, Generation: 2, RepairNonce: &second}
	reconciler.record(pass, restored)
	if report, _ := reconciler.take(owner); report != nil {
		t.Fatalf("generation 1's pass reported under generation 2: %+v", report)
	}
	queue()
	if report, _ := reconciler.take(owner); report == nil || report.Generation != 2 || *report.RepairNonce != second {
		t.Fatalf("report = %+v", report)
	}
	// A post that read generation 1 just before generation 2's report was
	// queued sends nothing, and leaves that report for the next post.
	state = installed
	if report, _ := reconciler.take(owner); report != nil {
		t.Fatalf("generation 2's report went under generation 1: %+v", report)
	}
	state = endpointconfig.HookState{Desired: endpointconfig.HookStateInstalled, Generation: 2, RepairNonce: &second}
	if report, _ := reconciler.take(owner); report == nil || report.Generation != 2 {
		t.Fatalf("a stale read dropped the newer report: %+v", report)
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
	// An earlier machine-wide drop-in names another binary: the installer
	// repeats its handlers in the user copy, and that copy reads complete.
	dropIn := filepath.Join(t.TempDir(), "20-kontext.json")
	swapManagedSettingsPaths(t, dropIn, filepath.Join(filepath.Dir(dropIn), "managed-settings.json"))
	machine, err := claudemanaged.TemplateJSON(hermetic.KontextBinary(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dropIn, machine, 0o644); err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{}
	if _, err := claudemanaged.MergeManagedHooksMirroring(settings, binary, machine); err != nil {
		t.Fatal(err)
	}
	mirrored, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probe.path, mirrored, 0o600); err != nil {
		t.Fatal(err)
	}
	if !probe.complete() {
		t.Fatal("the installer's mirrored copy reads incomplete")
	}
	// The same handlers with every hook turned off run none of them.
	settings["disableAllHooks"] = true
	disabled, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probe.path, disabled, 0o600); err != nil {
		t.Fatal(err)
	}
	if probe.complete() {
		t.Fatal("a mirrored copy with disableAllHooks reads complete")
	}
	if err := os.WriteFile(probe.path, mirrored, 0o600); err != nil {
		t.Fatal(err)
	}
	// The same copy once the drop-in is gone is not what the installer writes.
	if err := os.Remove(dropIn); err != nil {
		t.Fatal(err)
	}
	if probe.complete() {
		t.Fatal("a copy mirroring a removed drop-in reads complete")
	}
	if err := os.WriteFile(probe.path, []byte(`{"hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result := probe.action(false, healOutcome{claude: agentPass{attempted: true}})
	if result != (managedstream.HookActionResult{Agent: "claude_code", ScopeKind: "user", Status: managedstream.HookUnrestorable}) {
		t.Fatalf("action = %+v", result)
	}
}
