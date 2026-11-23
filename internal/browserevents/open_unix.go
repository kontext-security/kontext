//go:build !windows

package browserevents

import "syscall"

// openNoBlock makes opening a FIFO return at once instead of waiting for a
// writer, so a FIFO swapped in after the Lstat check cannot block startup.
const openNoBlock = syscall.O_NONBLOCK
