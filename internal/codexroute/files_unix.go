//go:build darwin || linux

// Only macOS routes Codex, but these work on Linux as well, where the
// router's tests run in CI.

package codexroute

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// lockFile takes path's lock, waiting for it unless wait is false: then it
// reports false when another process holds it.
func lockFile(path string, wait bool) (func(), bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	how := unix.LOCK_EX
	if !wait {
		how |= unix.LOCK_NB
	}
	if err := unix.Flock(int(lock.Fd()), how); err != nil {
		lock.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return func() {
		_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
		lock.Close()
	}, true, nil
}

// installBinary puts a copy of binary at path, only its owner may run, in a
// single rename. It clones the file where the volume can, which takes no
// space while the original stays, and copies it where it cannot.
func installBinary(binary *os.File, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary := filepath.Join(dir, fmt.Sprintf(".%s-%d.tmp", filepath.Base(path), os.Getpid()))
	_ = os.Remove(temporary)
	defer os.Remove(temporary)
	if err := cloneFile(binary, temporary); err != nil {
		if err := copyBinary(binary, temporary); err != nil {
			return err
		}
	}
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	// A new file, never the running one rewritten: the kernel keeps what it
	// checked of a binary's signature with the file.
	return os.Rename(temporary, path)
}

func copyBinary(binary *os.File, path string) error {
	info, err := binary.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, io.NewSectionReader(binary, 0, info.Size()))
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err
}

// fileIdentity names the file behind info and its version: a replaced or
// rewritten binary gets another.
func fileIdentity(info fs.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d", stat.Dev, stat.Ino, info.Size(), info.ModTime().UnixNano())
}
