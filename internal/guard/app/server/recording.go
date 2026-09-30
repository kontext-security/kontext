package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

// DeferredRecorder runs advisory inference and decision persistence outside
// the hook response path. Stop accepting hooks before calling Drain, and drain
// before closing the store or model. It never cancels work on hook disconnect.
type DeferredRecorder struct {
	slots    chan struct{}
	wg       sync.WaitGroup
	failures atomic.Int64
	diag     diagnostic.Logger
}

func NewDeferredRecorder(diag diagnostic.Logger) *DeferredRecorder {
	return &DeferredRecorder{slots: make(chan struct{}, 4), diag: diag}
}

func (r *DeferredRecorder) Submit(job func(context.Context) error) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		// Admission happens in the worker, never on the hook response path.
		r.slots <- struct{}{}
		defer func() { <-r.slots }()
		if err := job(context.Background()); err != nil {
			diagnostic.LogAlways(r.diag, "deferred decision record: %v (%d failed since start)\n", err, r.failures.Add(1))
		}
	}()
}

func (r *DeferredRecorder) Drain(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		r.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("drain deferred decision records: %w", ctx.Err())
	}
}
