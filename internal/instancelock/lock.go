// Package instancelock keeps one process per resource, on every OS. The OS
// holds the lock for the life of the open file and drops it when the process
// dies however it dies, so a lock can't go stale and needs no cleanup.
package instancelock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const pollInterval = 50 * time.Millisecond

var refreshInterval = time.Hour

// HeldError says another process holds the lock.
type HeldError struct {
	Path string
	// PID is the holder's process, 0 if it hasn't written it yet.
	PID int
}

func (e *HeldError) Error() string {
	if e.PID == 0 {
		return fmt.Sprintf("another process holds %s", e.Path)
	}
	return fmt.Sprintf("process %d holds %s", e.PID, e.Path)
}

// Lock is a held lock.
type Lock struct {
	file    *os.File
	release sync.Once
	stop    chan struct{}
	stopped chan struct{}
}

// PathForSocket names the lock for a socket, right beside it. One socket then has
// one lock whatever the home, the hostname or the spelling of its folder, and a
// folder the daemon can bind in is one it can lock in. The caller has to have
// checked the folder first, as it does for the socket.
func PathForSocket(socketPath string) string {
	return socketPath + ".lock"
}

// Acquire takes the lock at path, waiting up to wait for a holder to leave. A
// holder still there after that gives a *HeldError. The folder has to exist: it
// decides who else can reach the file, so creating it isn't this package's call.
// The file stays after a release: removing it would let two processes each lock
// a different file.
func Acquire(path string, wait time.Duration) (*Lock, error) {
	// Writing the PID through a link would overwrite whatever it points at, so
	// the open doesn't follow one, and the check is on what was opened.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|openNoFollow, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	deadline := time.Now().Add(wait)
	for {
		locked, err := tryLock(file)
		if err != nil {
			file.Close()
			return nil, err
		}
		if locked {
			break
		}
		if time.Now().After(deadline) {
			file.Close()
			return nil, &HeldError{Path: path, PID: readPID(path)}
		}
		time.Sleep(pollInterval)
	}
	if err := writePID(file); err != nil {
		file.Close()
		return nil, err
	}
	lock := &Lock{file: file, stop: make(chan struct{}), stopped: make(chan struct{})}
	go lock.keepFresh(path, refreshInterval)
	return lock, nil
}

// keepFresh touches the file for as long as the lock is held. Cleaners go by a
// file's age and don't care that it's locked: macOS deletes regular files under
// /tmp after three days, and the next process would then lock a new file.
func (l *Lock) keepFresh(path string, interval time.Duration) {
	defer close(l.stopped)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-ticker.C:
			now := time.Now()
			_ = os.Chtimes(path, now, now)
		}
	}
}

// Release gives the lock up. Calling it again does nothing.
func (l *Lock) Release() {
	l.release.Do(func() {
		close(l.stop)
		<-l.stopped
		l.file.Close()
	})
}

func writePID(file *os.File) error {
	if err := file.Truncate(0); err != nil {
		return err
	}
	_, err := file.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	return err
}

// readPID is for the message only, so anything unreadable reads as unknown.
func readPID(path string) int {
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}
