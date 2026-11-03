//go:build !windows

package instancelock

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const openNoFollow = unix.O_NOFOLLOW

func tryLock(file *os.File) (bool, error) {
	err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return false, nil
	}
	return err == nil, err
}
