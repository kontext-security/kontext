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

// WithDeadline returns a context in which the policy decision may wait for
// the policy until deadline.
func WithDeadline(ctx context.Context, deadline time.Time) context.Context {
	return context.WithValue(ctx, contextKey{}, deadline)
}

// Deadline reports until when the policy decision may wait for the policy,
// and false when the request was granted no hold.
func Deadline(ctx context.Context) (time.Time, bool) {
	deadline, ok := ctx.Value(contextKey{}).(time.Time)
	return deadline, ok && !deadline.IsZero()
}
