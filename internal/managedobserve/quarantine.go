//go:build !windows

package managedobserve

import (
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// quarantineUnapproved reports a com.apple.quarantine flag the user never
// approved. Gatekeeper then blocks the binary when launchd starts it, so the
// daemon never comes up. Clicking Open sets the 0x40 bit (0181 becomes 01c1)
// and later launchd starts are silent; an approved flag is not a problem.
func quarantineUnapproved(path string) bool {
	buf := make([]byte, 256)
	n, err := unix.Getxattr(path, "com.apple.quarantine", buf)
	if err != nil || n <= 0 {
		return false
	}
	field, _, _ := strings.Cut(string(buf[:n]), ";")
	flags, err := strconv.ParseUint(field, 16, 32)
	return err == nil && flags&0x40 == 0
}
