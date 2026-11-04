package managedobserve

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

// daemonStopBudget bounds a whole stop, so a stuck writer can't hold the daemon
// up until its service manager kills it. It stays below instanceLockWait: a
// replacement waits that long for this daemon to leave.
var daemonStopBudget = 3 * time.Second

// secondStopSignalExit is the exit code when an operator stops a daemon that is
// already stopping.
const secondStopSignalExit = 130

// StopOnSignal returns a context cancelled by the first stop signal, which lets
// the daemon write what it has answered. A second signal exits at once. On
// Windows, Go delivers console events as these signals; a process killed with
// TerminateProcess sees nothing.
func StopOnSignal(parent context.Context, log diagnostic.Logger) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-signals:
			cancel()
		case <-done:
			return
		}
		select {
		case <-signals:
			logAlways(log, "managed-observe daemon: second stop signal, exiting without finishing\n")
			os.Exit(secondStopSignalExit)
		case <-done:
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			signal.Stop(signals)
			close(done)
			cancel()
		})
	}
}

// stopClock holds one deadline for all the steps of a stop, from the first of
// them to ask.
type stopClock struct {
	once     sync.Once
	deadline time.Time
}

func (c *stopClock) start() {
	c.once.Do(func() { c.deadline = time.Now().Add(daemonStopBudget) })
}

func (c *stopClock) context() (context.Context, context.CancelFunc) {
	c.start()
	return context.WithDeadline(context.Background(), c.deadline)
}

// waitForBackgroundWork gives the daemon's loops a third of the budget. One that
// ignores its context mustn't spend the time the queued records need, and those
// are what the budget is for.
func waitForBackgroundWork(work *sync.WaitGroup, log diagnostic.Logger) {
	if !waitWithin(work, daemonStopBudget/3) {
		logAlways(log, "managed-observe daemon stopping with background work still running\n")
	}
}

// waitWithin reports whether the work ended in time.
func waitWithin(work *sync.WaitGroup, limit time.Duration) bool {
	done := make(chan struct{})
	go func() {
		work.Wait()
		close(done)
	}()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}
