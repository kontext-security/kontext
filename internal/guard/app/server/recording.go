package server

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

const (
	deferredRecordWorkers   = 4
	deferredRecordQueueSize = 256
)

var errRecorderClosed = errors.New("deferred recorder is closed")

// DeferredRecorder never drops a settled decision on saturation. Submit waits
// for queue space, so transports call it after writing the response and bound
// their outstanding request handlers. Stop/drain transports before Drain, and
// successfully drain this recorder before closing the store or model.
type DeferredRecorder struct {
	mu         sync.Mutex
	jobs       chan func(context.Context) error
	done       chan struct{}
	started    bool
	closed     bool
	submitters sync.WaitGroup
	workers    sync.WaitGroup
	failures   atomic.Int64
	logMu      sync.Mutex
	diag       diagnostic.Logger
}

func NewDeferredRecorder(diag diagnostic.Logger) *DeferredRecorder {
	return &DeferredRecorder{
		jobs: make(chan func(context.Context) error, deferredRecordQueueSize),
		done: make(chan struct{}),
		diag: diag,
	}
}

func (r *DeferredRecorder) Submit(job func(context.Context) error) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errRecorderClosed
	}
	if !r.started {
		r.started = true
		// Lazy startup owns no goroutines when daemon initialization fails.
		r.workers.Add(deferredRecordWorkers)
		for range deferredRecordWorkers {
			go r.run()
		}
	}
	// Admission and closing are serialized. Drain waits for every admitted
	// submitter before closing jobs, including senders waiting for queue space.
	r.submitters.Add(1)
	r.mu.Unlock()
	defer r.submitters.Done()
	r.jobs <- job
	return nil
}

func (r *DeferredRecorder) run() {
	defer r.workers.Done()
	for job := range r.jobs {
		if err := job(context.Background()); err != nil {
			r.logMu.Lock()
			diagnostic.LogAlways(r.diag, "deferred decision record: %v (%d failed since start)\n", err, r.failures.Add(1))
			r.logMu.Unlock()
		}
	}
}

func (r *DeferredRecorder) Drain(ctx context.Context) error {
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		go func() {
			r.submitters.Wait()
			close(r.jobs)
			r.workers.Wait()
			close(r.done)
		}()
	}
	r.mu.Unlock()
	// Repeated/timed-out drains share one completion channel. Accepted work
	// keeps running; callers must keep its resources alive until a drain succeeds.
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("drain deferred decision records: %w", ctx.Err())
	}
}
