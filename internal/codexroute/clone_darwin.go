package codexroute

import (
	"os"

	"golang.org/x/sys/unix"
)

// cloneFile clones binary at path, on volumes that can (APFS).
func cloneFile(binary *os.File, path string) error {
	return unix.Fclonefileat(int(binary.Fd()), unix.AT_FDCWD, path, 0)
}
