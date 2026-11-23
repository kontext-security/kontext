package managedobserve

import (
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/claudemanaged"
	"github.com/kontext-security/kontext/internal/endpointconfig"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/managedstream"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// hookReconciler turns the hook watch's passes into device.hook_actions
// (ADR-0012). It reports only once an admin acted on this device, which
// takes a confirmed v7 config with a generation above zero: a server that
// serves no v7 has a strict device schema without the field.
type hookReconciler struct {
	// state is the desired state the current enrolment's confirmed config
	// asks for, and the owner (endpointconfig.Owner) of that config; an
	// empty owner when no config of this enrolment is confirmed.
	state func() (endpointconfig.HookState, string)
	now   func() time.Time

	mu sync.Mutex
	// pending waits for an accepted post; last is the report last queued,
	// so a pass that finds the same again queues nothing. owner is the
	// enrolment both were made for.
	pending, last *managedstream.HookActions
	owner         string
}

func newHookReconciler(state func() (endpointconfig.HookState, string)) *hookReconciler {
	return &hookReconciler{state: state, now: time.Now}
}

// hookPass is the desired state one pass acts on, read as it starts.
type hookPass struct {
	state endpointconfig.HookState
	owner string
}

// begin reads the state a pass is about to act on. reporting is false when
// no admin acted on this device, so the pass reports nothing.
func (r *hookReconciler) begin() (pass hookPass, reporting bool) {
	if r == nil {
		return hookPass{}, false
	}
	state, owner := r.state()
	return hookPass{state: state, owner: owner}, state.Generation > 0 && owner != ""
}

// record queues the report of a pass that just finished, unless it says
// what the last one queued said. A pass that started under another state
// reports nothing: its result answers no request, and the change that moved
// the state runs a pass of its own.
func (r *hookReconciler) record(pass hookPass, results []managedstream.HookActionResult) {
	state, owner := r.state()
	r.mu.Lock()
	defer r.mu.Unlock()
	if state.Generation == 0 || owner == "" {
		r.pending, r.last, r.owner = nil, nil, ""
		return
	}
	if owner != pass.owner || !state.Equal(pass.state) {
		return
	}
	if r.owner != owner {
		r.pending, r.last, r.owner = nil, nil, owner
	}
	report := &managedstream.HookActions{
		Schema:      managedstream.HookActionsSchema,
		Desired:     state.Desired,
		Generation:  state.Generation,
		RepairNonce: state.RepairNonce,
		FinishedAt:  r.now().UTC().Format(time.RFC3339Nano),
		Results:     keepRestored(r.pending, state, results),
	}
	if r.last != nil && r.last.Same(*report) {
		return
	}
	r.pending, r.last = report, report
}

// keepRestored keeps a repair the cloud hasn't heard of yet: while a report
// for the same request waits to go, a later pass that finds the repaired
// hooks in place leaves that scope's "restored" as it is.
func keepRestored(pending *managedstream.HookActions, state endpointconfig.HookState, results []managedstream.HookActionResult) []managedstream.HookActionResult {
	if pending == nil || pending.Desired != state.Desired || pending.Generation != state.Generation ||
		(pending.RepairNonce == nil) != (state.RepairNonce == nil) || state.Nonce() != nonceOf(pending) {
		return results
	}
	kept := slices.Clone(results)
	for i, result := range kept {
		if result.Status != managedstream.HookInPlace {
			continue
		}
		for _, earlier := range pending.Results {
			if earlier.Status == managedstream.HookRestored && earlier.Agent == result.Agent &&
				earlier.ScopeKind == result.ScopeKind && earlier.ScopeID == result.ScopeID {
				kept[i].Status = managedstream.HookRestored
			}
		}
	}
	return kept
}

func nonceOf(report *managedstream.HookActions) string {
	if report.RepairNonce == nil {
		return ""
	}
	return *report.RepairNonce
}

// take is the stream's view: the report waiting to go, and a func that
// marks it sent. A newer report queued meanwhile stays pending. A report
// made for another enrolment, or for a state the cloud no longer serves
// (a re-enrolment, a fallback to v6), is dropped: it would go with the
// wrong token, or fail a strict schema. flushOwner is the owner of the token
// the post goes with; a report goes only with the enrolment it was made for.
func (r *hookReconciler) take(flushOwner string) (*managedstream.HookActions, func()) {
	if r == nil {
		return nil, nil
	}
	state, owner := r.state()
	r.mu.Lock()
	defer r.mu.Unlock()
	pending := r.pending
	if pending == nil {
		return nil, nil
	}
	if owner == "" || owner != r.owner || state.Generation == 0 {
		r.pending, r.last, r.owner = nil, nil, ""
		return nil, nil
	}
	// A report newer than the state read above was queued after that read:
	// it stays for the next post, which reads the state again.
	if pending.Generation > state.Generation {
		return nil, nil
	}
	// A flush that started under another token gets nothing, and leaves the
	// report for the next post that goes with its enrolment's token.
	if flushOwner != owner {
		return nil, nil
	}
	return pending, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.pending == pending {
			r.pending = nil
		}
	}
}

// claudeHookProbe reads Claude Code's Kontext hooks back: on a self-serve Mac
// the user's settings, which the daemon writes; on a packaged one the
// machine-wide drop-in, which only the package writes.
type claudeHookProbe struct {
	selfServe bool
	home      string
	path      string
	binary    string
	validate  func([]byte) (string, error)
}

func newClaudeHookProbe(selfServe bool, home, binary string) *claudeHookProbe {
	probe := &claudeHookProbe{selfServe: selfServe, home: home, binary: binary}
	if !selfServe {
		return probe
	}
	defs, err := hookinstall.SetupDefinitions(hookinstall.User, home)
	if err != nil {
		return nil
	}
	for _, def := range defs {
		if def.Agent == "claude_code" && len(def.Files) == 1 {
			probe.path, probe.validate = def.Files[0].Path, def.Validate
			return probe
		}
	}
	return nil
}

// complete reports whether Kontext's full hook set is in place: naming the
// binary the daemon installs, or exactly the handlers the installer writes
// when it repeats a machine-wide source's (an earlier drop-in naming another
// binary), so that Claude runs each once.
func (p *claudeHookProbe) complete() bool {
	if !p.selfServe {
		inPlace, _ := packageHooks()
		return inPlace
	}
	if privacyfolder.Guarded(p.home, p.path) {
		return false
	}
	raw, err := os.ReadFile(p.path)
	if err != nil {
		return false
	}
	return namesBinary(raw, p.validate, p.binary) || claudemanaged.UserHooksMatch(raw, p.binary, machineClaudeSettings()...)
}

// machineClaudeSettings reads Claude's machine-wide settings the way the
// installer does, skipping any path in a privacy-guarded folder.
func machineClaudeSettings() [][]byte {
	var sources [][]byte
	for _, path := range claudemanaged.MachineSettingsFiles(managedSettingsDropInPath, managedSettingsFilePath) {
		if privacyfolder.Guarded("", path) {
			continue
		}
		if raw, err := os.ReadFile(path); err == nil {
			sources = append(sources, raw)
		}
	}
	return sources
}

// foreign reports a settings file Kontext can't merge its entries into:
// present, readable, and not a JSON object. The installer refuses those
// rather than overwrite them.
func (p *claudeHookProbe) foreign() bool {
	if privacyfolder.Guarded(p.home, p.path) {
		return true
	}
	raw, err := os.ReadFile(p.path)
	if errors.Is(err, os.ErrNotExist) || err != nil {
		return false
	}
	var object map[string]json.RawMessage
	return json.Unmarshal(raw, &object) != nil || object == nil
}

// action is the status of Claude Code's Kontext hooks after a pass, read back
// after any repair.
func (p *claudeHookProbe) action(before bool, outcome healOutcome) managedstream.HookActionResult {
	result := managedstream.HookActionResult{Agent: "claude_code", ScopeKind: "user"}
	if !p.selfServe {
		result.ScopeKind = "managed_dropin"
	}
	result.Status = claudeHookStatus(claudeHookObservation{
		selfServe: p.selfServe,
		optOut:    outcome.optOut,
		before:    before,
		after:     p.complete(),
		pass:      outcome.claude,
		foreign:   p.selfServe && p.foreign(),
	})
	return result
}

type claudeHookObservation struct {
	selfServe, optOut bool
	// before and after: Kontext's full set was in place before the pass,
	// and is when read back after it.
	before, after bool
	pass          agentPass
	foreign       bool
}

func claudeHookStatus(o claudeHookObservation) string {
	switch {
	case o.optOut:
		return managedstream.HookAdminOff
	case o.after && o.before:
		return managedstream.HookInPlace
	case o.after:
		return managedstream.HookRestored
	case !o.selfServe:
		// The drop-in is root's; the daemon never writes it.
		return managedstream.HookNeedsPrivileged
	case o.pass.guarded || o.foreign:
		return managedstream.HookNotOurs
	case o.pass.attempted:
		return managedstream.HookUnrestorable
	default:
		return managedstream.HookMissing
	}
}
