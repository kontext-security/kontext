// Package instancelock keeps one process per resource, on every OS. The OS
// holds the lock for the life of the open file and drops it when the process
// dies however it dies, so a lock can't go stale and needs no cleanup.
package instancelock

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/platform"
)

const pollInterval = 50 * time.Millisecond

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
}

var hostname = os.Hostname

// machineKey keeps Linux machines sharing a home over a network from refusing
// each other's daemons. Only there: a Mac's hostname follows the network, which
// would change the lock's name under a running daemon and leave a file for each
// name, and Windows keeps this folder per machine.
func machineKey(goos string) string {
	if goos != "linux" {
		return ""
	}
	host, _ := hostname()
	return host
}

// PathForSocket names the lock for a socket. It's in the user's state folder,
// not beside the socket: on macOS and Linux that is under /tmp, where another
// user can create the folder first.
func PathForSocket(socketPath string) (string, error) {
	absolute, err := filepath.Abs(socketPath)
	if err != nil {
		return "", err
	}
	// One socket has one lock however its folder is spelled, as with /tmp and
	// /private/tmp on macOS. A folder that isn't there yet has no second spelling.
	if dir, err := filepath.EvalSymlinks(filepath.Dir(absolute)); err == nil {
		absolute = filepath.Join(dir, filepath.Base(absolute))
	}
	state, err := platform.UserStateDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(machineKey(runtime.GOOS) + "\x00" + absolute))
	return filepath.Join(state, "locks", "socket-"+hex.EncodeToString(sum[:8])+".lock"), nil
}

// Acquire takes the lock at path, waiting up to wait for a holder to leave. A
// holder still there after that gives a *HeldError. The file stays after a
// release: removing it would let two processes each lock a different file.
func Acquire(path string, wait time.Duration) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
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
	return &Lock{file: file}, nil
}

// Release gives the lock up. Calling it again does nothing.
func (l *Lock) Release() {
	l.release.Do(func() { l.file.Close() })
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
