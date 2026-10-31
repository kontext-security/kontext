package localruntime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
)

const (
	// duplicateHookWindow is how long a settled hook event stays known, and the
	// longest a copy waits for an unsettled first. An agent starts every hook
	// configured for an event at once, so a second Kontext hook arrives
	// milliseconds after the first; a legitimate repeat carries a new tool call
	// id, different content, or comes later.
	duplicateHookWindow = 3 * time.Second
	// maxTrackedHookEvents bounds the events held at once. Past it, a new event
	// is processed untracked.
	maxTrackedHookEvents = 4096
)

// hookKey identifies one hook event across the hook processes an agent runs
// for it.
type hookKey [sha256.Size]byte

// duplicateHooks answers and records each hook event once when the agent runs
// Kontext's hook for it more than once: Kontext named in two hook files, a
// stale copy, a hand-edited config. Copies of a decision-gating event share one
// evaluation; copies of a non-blocking event leave one ledger event. It never
// decides anything itself: a copy whose first failed, or has not settled
// within the window, is processed as if it came alone.
type duplicateHooks struct {
	mu        sync.Mutex
	now       func() time.Time
	window    time.Duration
	events    map[hookKey]*hookCall
	nextSweep time.Time
}

// hookCall is an event's first copy. done closes once it settles; a successful
// result is kept until expires.
type hookCall struct {
	done    chan struct{}
	result  hook.Result
	ok      bool
	expires time.Time // zero while the first copy is in flight
}

func newDuplicateHooks() *duplicateHooks {
	return &duplicateHooks{
		now:    time.Now,
		window: duplicateHookWindow,
		events: map[hookKey]*hookCall{},
	}
}

// hookEventKey keys an event by agent, session, hook and the tool call id
// that names one call. An event without one (a prompt, a session start, a
// stop) keys on its whole request instead: the agent hands every hook the same
// stdin and Kontext decodes it deterministically, so copies of one event are
// identical, while the same prompt typed again later falls outside the window.
// A turn id would not do: Claude Code sends none, and a Codex turn can submit
// more than one prompt and stop more than once.
func hookEventKey(event hook.Event, req *EvaluateRequest) (hookKey, bool) {
	var identity []byte
	for _, field := range []string{event.Agent, event.SessionID, event.HookName.String(), event.ToolUseID} {
		// Length-prefixed, so no two field lists encode alike.
		identity = binary.BigEndian.AppendUint64(identity, uint64(len(field)))
		identity = append(identity, field...)
	}
	if event.ToolUseID == "" {
		payload, err := json.Marshal(req)
		if err != nil {
			return hookKey{}, false
		}
		identity = append(identity, payload...)
	}
	return sha256.Sum256(identity), true
}

// do runs process for the event unless a copy of it is in flight or settled
// within the window; then it returns that copy's result and reports the
// duplicate. Only a successful result is shared.
func (d *duplicateHooks) do(event hook.Event, req *EvaluateRequest, process func() (hook.Result, error)) (result hook.Result, duplicate bool, err error) {
	key, ok := hookEventKey(event, req)
	if !ok {
		result, err = process()
		return result, false, err
	}
	d.mu.Lock()
	now := d.now()
	d.sweep(now)
	if call, found := d.events[key]; found {
		if call.expires.IsZero() {
			d.mu.Unlock()
			return d.await(call, process)
		}
		if now.Before(call.expires) {
			result = call.result
			d.mu.Unlock()
			return result, true, nil
		}
	}
	if len(d.events) >= maxTrackedHookEvents {
		d.mu.Unlock()
		result, err = process()
		return result, false, err
	}
	call := &hookCall{done: make(chan struct{})}
	d.events[key] = call
	d.mu.Unlock()

	settled := false
	defer func() {
		// A panic must not leave copies waiting on a call that ended.
		if !settled {
			d.settle(key, call, hook.Result{}, false)
		}
	}()
	result, err = process()
	d.settle(key, call, result, err == nil)
	settled = true
	return result, false, err
}

// await waits for an unsettled first copy, at most the window.
func (d *duplicateHooks) await(call *hookCall, process func() (hook.Result, error)) (hook.Result, bool, error) {
	timer := time.NewTimer(d.window)
	defer timer.Stop()
	select {
	case <-call.done:
		if call.ok {
			return call.result, true, nil
		}
	case <-timer.C:
	}
	result, err := process()
	return result, false, err
}

// settle publishes the first copy's outcome. A success stays for the window; a
// failure is forgotten, so the next copy processes itself.
func (d *duplicateHooks) settle(key hookKey, call *hookCall, result hook.Result, ok bool) {
	d.mu.Lock()
	if ok {
		call.result, call.ok = result, true
		call.expires = d.now().Add(d.window)
	} else if d.events[key] == call {
		delete(d.events, key)
	}
	d.mu.Unlock()
	close(call.done)
}

// sweep drops settled events past their window, at most once a window unless
// the table is full.
func (d *duplicateHooks) sweep(now time.Time) {
	if now.Before(d.nextSweep) && len(d.events) < maxTrackedHookEvents {
		return
	}
	for key, call := range d.events {
		if !call.expires.IsZero() && !now.Before(call.expires) {
			delete(d.events, key)
		}
	}
	d.nextSweep = now.Add(d.window)
}
