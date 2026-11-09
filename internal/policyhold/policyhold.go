// Package policyhold carries a granted policy hold from the local runtime's
// connection handler to the policy decision.
//
// A fresh daemon may not have its policy yet when the first tool calls
// arrive. When the hook said it can wait (the hold capability) and the daemon
// told it to (a hold frame), the request's context carries the time until
// which the decision may wait for the policy. A request without a hold never
// waits, so a hook that predates the capability keeps its original budget.
package policyhold

import (
	"context"
	"time"
)

type contextKey struct{}

type hold struct {
	deadline time.Time
	stop     <-chan struct{}
}

// WithDeadline returns a context in which the policy decision may wait for
// the policy until deadline. The returned context is not cancelled with
// ctx: a held call is decided and recorded to the end even when the daemon
// stops during the hold, as it would be once the hold ran out. ctx's
// cancellation instead ends the wait early (see Deadline).
func WithDeadline(ctx context.Context, deadline time.Time) context.Context {
	return context.WithValue(context.WithoutCancel(ctx), contextKey{}, hold{deadline: deadline, stop: ctx.Done()})
}

// Deadline reports until when the policy decision may wait for the policy,
// a channel that closes when the wait should end early because the daemon
// is stopping (nil when it never will), and false when the request was
// granted no hold.
func Deadline(ctx context.Context) (deadline time.Time, stop <-chan struct{}, ok bool) {
	h, ok := ctx.Value(contextKey{}).(hold)
	if !ok || h.deadline.IsZero() {
		return time.Time{}, nil, false
	}
	return h.deadline, h.stop, true
}
