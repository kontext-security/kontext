package managedobserve

import (
	"context"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
)

// turnEndSettle bounds how long an upload at a turn's end waits for the turn's
// last records. They are written after their hooks are answered, so an upload
// sent the moment Stop arrives could leave them for the next one.
const turnEndSettle = 2 * time.Second

// turnEnd sends the stream when a turn or a session ends, without waiting for
// the tick. A hosted session's machine can be paused or gone seconds after its
// last turn, and what the daemon still held then never reached the cloud.
type turnEnd struct {
	now chan struct{}
	// pending counts the records answered but not yet written. Set once, before
	// the stream starts.
	pending func() int
	settle  time.Duration
}

func newTurnEnd() *turnEnd {
	return &turnEnd{now: make(chan struct{}, 1), settle: turnEndSettle}
}

// observe asks for an upload after the events that close a turn or a session.
// A request already waiting covers this one too.
func (t *turnEnd) observe(event hook.Event) {
	if event.HookName != hook.HookStop && event.HookName != hook.HookSessionEnd {
		return
	}
	select {
	case t.now <- struct{}{}:
	default:
	}
}

// wait returns once the records still being written are in the store, or the
// settle time has passed.
func (t *turnEnd) wait(ctx context.Context) {
	if t.pending == nil || t.pending() == 0 {
		return
	}
	deadline := time.NewTimer(t.settle)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for t.pending() > 0 {
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			return
		case <-poll.C:
		}
	}
}
