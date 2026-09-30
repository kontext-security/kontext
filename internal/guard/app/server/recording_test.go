package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

func TestDeferredRecorderBoundsBacklogWithoutWaiting(t *testing.T) {
	var log bytes.Buffer
	r := NewDeferredRecorder(diagnostic.New(&log, true))
	started := make(chan struct{}, deferredRecordWorkers)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		_ = r.Drain(context.Background())
	})
	var completed atomic.Int64
	for range deferredRecordWorkers {
		r.Submit(func(context.Context) error {
			started <- struct{}{}
			<-release
			completed.Add(1)
			return nil
		})
	}
	for range deferredRecordWorkers {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("workers did not start")
		}
	}
	const overflow = 10000
	submitted := make(chan struct{})
	go func() {
		defer close(submitted)
		for range deferredRecordQueueSize + overflow {
			r.Submit(func(context.Context) error { completed.Add(1); return nil })
		}
	}()
	select {
	case <-submitted:
	case <-time.After(time.Second):
		t.Fatal("submission waited for a stalled worker")
	}
	if len(r.jobs) != deferredRecordQueueSize || r.dropped.Load() != overflow || completed.Load() != 0 {
		t.Fatalf("queued=%d dropped=%d completed=%d", len(r.jobs), r.dropped.Load(), completed.Load())
	}
	releaseOnce.Do(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if got := completed.Load(); got != deferredRecordWorkers+deferredRecordQueueSize {
		t.Fatalf("completed %d jobs; rejected work must never run", got)
	}
	if !strings.Contains(log.String(), "10000 total since start") || !strings.Contains(log.String(), "decision rows and annotations were not saved") {
		t.Fatalf("missing overload diagnostic: %s", log.String())
	}
}

func TestDeferredRecorderDrainTimeoutAndRetry(t *testing.T) {
	r := NewDeferredRecorder(diagnostic.New(io.Discard, true))
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		_ = r.Drain(context.Background())
	})
	var completed atomic.Int64
	r.Submit(func(ctx context.Context) error {
		<-release
		if ctx.Err() != nil {
			return ctx.Err()
		}
		completed.Add(1)
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 10 {
		if err := r.Drain(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("drain should time out while retaining accepted work: %v", err)
		}
	}
	r.Submit(func(context.Context) error { completed.Add(100); return nil })
	releaseOnce.Do(func() { close(release) })
	for range 2 {
		if err := r.Drain(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if completed.Load() != 1 || r.dropped.Load() != 1 || r.failures.Load() != 0 {
		t.Fatalf("completed=%d dropped=%d failed=%d", completed.Load(), r.dropped.Load(), r.failures.Load())
	}
}

func TestDeferredRecorderConcurrentSubmitAndDrain(t *testing.T) {
	r := NewDeferredRecorder(diagnostic.New(io.Discard, true))
	const producers, perProducer = 8, 1000
	var completed atomic.Int64
	release := make(chan struct{})
	r.Submit(func(context.Context) error {
		<-release
		completed.Add(1)
		return nil
	})
	var group sync.WaitGroup
	var drains sync.WaitGroup
	start := make(chan struct{})
	for range producers {
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for range perProducer {
				r.Submit(func(context.Context) error { completed.Add(1); return nil })
			}
		}()
	}
	for range 4 {
		drains.Add(1)
		go func() {
			defer drains.Done()
			<-start
			if err := r.Drain(context.Background()); err != nil {
				t.Errorf("concurrent drain: %v", err)
			}
		}()
	}
	close(start)
	group.Wait()
	close(release)
	drains.Wait()
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := completed.Load() + r.dropped.Load(); got != producers*perProducer+1 {
		t.Fatalf("accounted for %d jobs, want %d", got, producers*perProducer+1)
	}
}

func TestDeferredRecorderContinuesAfterJobFailure(t *testing.T) {
	var log bytes.Buffer
	r := NewDeferredRecorder(diagnostic.New(&log, true))
	var completed atomic.Int64
	r.Submit(func(context.Context) error { return errors.New("test record failure") })
	for range 20 {
		r.Submit(func(context.Context) error { completed.Add(1); return nil })
	}
	if err := r.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if completed.Load() != 20 || r.failures.Load() != 1 || !strings.Contains(log.String(), "test record failure") {
		t.Fatalf("completed=%d failed=%d log=%s", completed.Load(), r.failures.Load(), log.String())
	}
}
