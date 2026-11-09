package main

import (
	"os"
	"path/filepath"
)

// maxDaemonLogBytes caps the log a daemon without error output keeps. Past it
// the log starts over, and the previous one stays beside it as daemon.log.1.
const maxDaemonLogBytes = 10 << 20

// openDaemonLog opens dir/daemon.log for appending, owner-only, rotating it
// first if it has grown past its cap.
func openDaemonLog(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "daemon.log")
	if info, err := os.Stat(path); err == nil && info.Size() > maxDaemonLogBytes {
		_ = os.Rename(path, path+".1")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}
