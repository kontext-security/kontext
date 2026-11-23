//go:build !windows

package browserevents

import (
	"os"
	"syscall"
)

// openNoBlock makes opening a FIFO return at once instead of waiting for a
// writer, so a FIFO swapped in after the Lstat check cannot block startup.
const openNoBlock = syscall.O_NONBLOCK

// onlyOwnerMode says whether the file's mode gives no access to anyone but
// its owner.
func onlyOwnerMode(info os.FileInfo) bool {
	return info.Mode().Perm()&0o077 == 0
}
