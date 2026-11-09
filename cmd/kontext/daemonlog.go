package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// maxDaemonLogBytes caps the log a daemon without error output keeps, checked
// at each start: past it the log starts over, and the previous one stays beside
// it as daemon.log.1. A daemon writes only its errors there, so one run adds
// little.
const maxDaemonLogBytes = 10 << 20

// openDaemonLog opens dir/daemon.log for appending, owner-only, rotating it
// first if it has grown past its cap. A rotation that fails, for instance while
// the same user's daemon in another session holds the log open, is noted in it.
func openDaemonLog(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "daemon.log")
	var rotateErr error
	if info, err := os.Stat(path); err == nil && info.Size() > maxDaemonLogBytes {
		rotateErr = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil && rotateErr != nil {
		fmt.Fprintf(f, "daemon.log is past %d MB and couldn't be rotated: %v\n", maxDaemonLogBytes>>20, rotateErr)
	}
	return f, err
}
