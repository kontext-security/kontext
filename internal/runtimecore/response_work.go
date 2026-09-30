package runtimecore

import "context"

// MaxPendingHookRequests bounds decoded requests and post-response work held
// outside the recorder queue. Transports acquire admission before evaluation.
const MaxPendingHookRequests = 64

type responseWorkKey struct{}
type responseWork struct{ jobs []func() }

// WithResponseWork lets a transport hand off recording after writing the settled
// response. The returned finish must run even when the client disconnects or the
// write fails, and shutdown must wait for it before closing the recorder/store.
// Registration and finish belong to the same request goroutine.
func WithResponseWork(ctx context.Context) (context.Context, func()) {
	w := &responseWork{}
	return context.WithValue(ctx, responseWorkKey{}, w), func() {
		jobs := w.jobs
		w.jobs = nil
		for _, job := range jobs {
			job()
		}
	}
}

// AfterResponse registers work with the transport. False means a direct caller
// without a response boundary; it must submit the work itself before returning.
func AfterResponse(ctx context.Context, job func()) bool {
	w, ok := ctx.Value(responseWorkKey{}).(*responseWork)
	if !ok {
		return false
	}
	w.jobs = append(w.jobs, job)
	return true
}
