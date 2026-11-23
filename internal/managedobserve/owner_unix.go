//go:build unix

package managedobserve

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ensurePrivateOwner refuses a socket directory another uid owns and narrows its mode to 0700.
func ensurePrivateOwner(dir string, info os.FileInfo) error {
	if err := checkOwner(dir, info); err != nil {
		return err
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func checkOwner(dir string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("socket directory ownership is unavailable")
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("socket directory %s is owned by uid %d, want %d", dir, stat.Uid, os.Getuid())
	}
	return nil
}

// checkPrivateOwner is ensurePrivateOwner without changes: a client only
// checks that the directory is this user's and nobody else can write to it.
func checkPrivateOwner(dir string, info os.FileInfo) error {
	if err := checkOwner(dir, info); err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("socket directory %s is writable by others", dir)
	}
	return nil
}
