//go:build !windows

package browserevents

import (
	"os"
	"syscall"
)

// openNoBlock makes opening a FIFO return at once instead of waiting for a
// writer, so a FIFO swapped in after the Lstat check cannot block startup.
const openNoBlock = syscall.O_NONBLOCK

// trustedFile says whether only this user could have written the file: it
// is this user's, and its mode lets no one else write it, whatever its
// privacy. Others may have read it, such as a backup restored 0644; it is
// written again private.
func trustedFile(_ bool, info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid() && info.Mode().Perm()&0o022 == 0
}
