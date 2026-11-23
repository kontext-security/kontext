package managedobserve

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

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
	state func() endpointconfig.HookState
	now   func() time.Time

	mu sync.Mutex
	// pending waits for an accepted post; last is the report last queued,
	// so a pass that finds the same again queues nothing.
	pending, last *managedstream.HookActions
}

func newHookReconciler(state func() endpointconfig.HookState) *hookReconciler {
	return &hookReconciler{state: state, now: time.Now}
}

// active reports whether an admin's desired state applies to this device.
func (r *hookReconciler) active() bool {
	return r != nil && r.state().Generation > 0
}

// record queues the report of a pass that just finished, unless it says
// what the last one queued said.
func (r *hookReconciler) record(results []managedstream.HookActionResult) {
	state := r.state()
	r.mu.Lock()
	defer r.mu.Unlock()
	if state.Generation == 0 {
		r.pending, r.last = nil, nil
		return
	}
	report := &managedstream.HookActions{
		Schema:      managedstream.HookActionsSchema,
		Desired:     state.Desired,
		Generation:  state.Generation,
		RepairNonce: state.RepairNonce,
		FinishedAt:  r.now().UTC().Format(time.RFC3339Nano),
		Results:     results,
	}
	if r.last != nil && r.last.Same(*report) {
		return
	}
	r.pending, r.last = report, report
}

// take is the stream's view: the report waiting to go, and a func that
// marks it sent. A newer report queued meanwhile stays pending.
func (r *hookReconciler) take() (*managedstream.HookActions, func()) {
	if r == nil {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pending := r.pending
	if pending == nil {
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

// complete reports whether Kontext's full hook set is in place, naming the
// binary the daemon installs.
func (p *claudeHookProbe) complete() bool {
	if !p.selfServe {
		inPlace, _ := packageHooks()
		return inPlace
	}
	if privacyfolder.Guarded(p.home, p.path) {
		return false
	}
	raw, err := os.ReadFile(p.path)
	return err == nil && namesBinary(raw, p.validate, p.binary)
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

// sameHookState compares two states by value: the nonce is a pointer.
func sameHookState(a, b endpointconfig.HookState) bool {
	return a.Desired == b.Desired && a.Generation == b.Generation && a.Nonce() == b.Nonce()
}
