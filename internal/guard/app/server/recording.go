package server

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

const (
	deferredRecordWorkers   = 4
	deferredRecordQueueSize = 256
)

// DeferredRecorder runs advisory inference and decision persistence outside
// the hook response path. Stop accepting hooks before calling Drain, and drain
// before closing the store or model. It never cancels work on hook disconnect.
// At saturation it drops the newest record, including its annotations, instead
// of delaying authorization. Workers report dropped counts outside the hook path.
type DeferredRecorder struct {
	mu       sync.Mutex
	jobs     chan func(context.Context) error
	done     chan struct{}
	started  bool
	closed   bool
	dropped  atomic.Int64
	failures atomic.Int64
	logMu    sync.Mutex
	reported int64
	diag     diagnostic.Logger
}

func NewDeferredRecorder(diag diagnostic.Logger) *DeferredRecorder {
	return &DeferredRecorder{
		jobs: make(chan func(context.Context) error, deferredRecordQueueSize),
		done: make(chan struct{}),
		diag: diag,
	}
}

func (r *DeferredRecorder) Submit(job func(context.Context) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		r.dropped.Add(1)
		return
	}
	if !r.started {
		r.started = true
		// Start lazily so an unused recorder, including failed daemon startup,
		// owns no goroutines. This fixed pool never grows with the input rate.
		var workers sync.WaitGroup
		workers.Add(deferredRecordWorkers)
		for range deferredRecordWorkers {
			go func() {
				defer workers.Done()
				for job := range r.jobs {
					if err := job(context.Background()); err != nil {
						r.logMu.Lock()
						diagnostic.LogAlways(r.diag, "deferred decision record: %v (%d failed since start)\n", err, r.failures.Add(1))
						r.logMu.Unlock()
					}
					r.reportDropped()
				}
			}()
		}
		go func() {
			workers.Wait()
			close(r.done)
		}()
	}
	select {
	case r.jobs <- job:
	default:
		// Never wait for space, retain a rejected closure, start a fallback
		// goroutine, or perform inference, writes or logging on the hook path.
		r.dropped.Add(1)
	}
}

func (r *DeferredRecorder) Drain(ctx context.Context) error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.jobs)
		if !r.started {
			close(r.done)
		}
	}
	r.mu.Unlock()
	// All callers share one completion channel, even after a timed-out drain.
	// Accepted jobs keep running; later submissions are rejected.
	select {
	case <-r.done:
		r.reportDropped()
		return nil
	case <-ctx.Done():
		return fmt.Errorf("drain deferred decision records: %w", ctx.Err())
	}
}

func (r *DeferredRecorder) reportDropped() {
	r.logMu.Lock()
	defer r.logMu.Unlock()
	total := r.dropped.Load()
	if total != r.reported {
		diagnostic.LogAlways(r.diag, "deferred decision recording: dropped %d records (%d total since start; queue full or recorder closed); their decision rows and annotations were not saved\n", total-r.reported, total)
		r.reported = total
	}
}
