//go:build windows

// Package busyfile reads, replaces and removes small state files that
// another process may have open at that moment: the daemon replaces them
// while doctor reads them. Windows refuses a rename or a remove while a
// reader has the file open, and an open while the file is being replaced.
// The functions here try again for a moment; elsewhere they are the plain
// os calls.
package busyfile

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// wait bounds the retries. Another handle keeps such a file busy for as long
// as one read or one rename takes.
const wait = 250 * time.Millisecond

const errorSharingViolation syscall.Errno = 32

// busy reports what Windows answers while another handle has the file:
// access denied for a rename over a file that is open, a sharing violation
// for an open of a file that is being replaced or a remove of one that is
// open.
func busy(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && (errno == syscall.ERROR_ACCESS_DENIED || errno == errorSharingViolation)
}

// retry tries again every few milliseconds: the other handle is held for
// less than that, and a reader that polls opens the file again right away,
// so many short tries find a gap where few long ones do not.
func retry(do func() error) error {
	deadline := time.Now().Add(wait)
	for pause := time.Millisecond; ; pause = min(2*pause, 4*time.Millisecond) {
		err := do()
		if err == nil || !busy(err) || time.Now().After(deadline) {
			return err
		}
		time.Sleep(pause)
	}
}

// Rename renames from over to, as os.Rename does.
func Rename(from, to string) error {
	return retry(func() error { return os.Rename(from, to) })
}

// ReadFile reads path, as os.ReadFile does.
func ReadFile(path string) (data []byte, err error) {
	err = retry(func() error {
		data, err = os.ReadFile(path)
		return err
	})
	return data, err
}

// Remove removes path, as os.Remove does.
func Remove(path string) error {
	return retry(func() error { return os.Remove(path) })
}
