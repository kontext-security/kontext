//go:build darwin || linux

package codexroute

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// JobLog is where the proxy job logs, given the home whose route it serves
// and where it would log otherwise: once its standard error is the job's
// log at LogPath, as launchd opens it from the plist, a log that starts again
// before it would pass LogLimit, since launchd never trims it.
func JobLog(home string, fallback io.Writer) io.Writer {
	if home == "" {
		return fallback
	}
	return jobLogFor(LogPath(home), LogLimit, fallback, os.Stdout, os.Stderr)
}

// jobLogFor is JobLog for the log at path, kept under limit, where stdout and
// stderr are the process's standard output and error: fallback unless stderr
// is the file at path.
func jobLogFor(path string, limit int64, fallback io.Writer, stdout, stderr *os.File) io.Writer {
	if !isFileAt(stderr, path) {
		return fallback
	}
	log := &jobLog{path: path, limit: limit, files: []*os.File{stderr}}
	if stdout != stderr && isFileAt(stdout, path) {
		log.files = append(log.files, stdout)
	}
	return log
}

// isFileAt reports whether file is the file at path.
func isFileAt(file *os.File, path string) bool {
	if file == nil {
		return false
	}
	info, err := file.Stat()
	if err != nil {
		return false
	}
	at, err := os.Stat(path)
	return err == nil && os.SameFile(info, at)
}

// jobLog is the log that files, standard error first, write to. Before a
// write would take it past limit, it moves to path + ".1", in place of the
// last one, and the files point at a new one at path: whatever else writes to
// them, as a crash's trace, goes there too.
type jobLog struct {
	mu    sync.Mutex
	path  string
	limit int64
	files []*os.File
	// failed is the last reason the log could not start again, written to it
	// once.
	failed string
}

func (l *jobLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	failed := ""
	if err := l.makeRoom(int64(len(p))); err != nil {
		failed = err.Error()
	}
	if failed != "" && failed != l.failed {
		fmt.Fprintf(l.files[0], "codex-proxy %s log not started again: %s\n", time.Now().Format("2006/01/02 15:04:05"), failed)
	}
	l.failed = failed
	return l.files[0].Write(p)
}

// makeRoom readies the log for n more bytes: it follows the log at path once
// another run of the job started it again, or it was deleted, and starts it
// again itself when n more bytes would take a log with anything in it past
// the limit.
func (l *jobLog) makeRoom(n int64) error {
	info, err := l.files[0].Stat()
	if err != nil {
		return err
	}
	if at, err := os.Stat(l.path); err != nil || !os.SameFile(info, at) {
		if err := l.point(); err != nil {
			return err
		}
		if info, err = l.files[0].Stat(); err != nil {
			return err
		}
	}
	if info.Size() == 0 || info.Size()+n <= l.limit {
		return nil
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return err
	}
	return l.point()
}

// point points the files at the log at path, made when there is none.
func (l *jobLog) point() error {
	log, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer log.Close()
	for _, file := range l.files {
		if err := unix.Dup2(int(log.Fd()), int(file.Fd())); err != nil {
			return err
		}
	}
	return nil
}
