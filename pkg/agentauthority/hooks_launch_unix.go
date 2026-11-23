//go:build !windows

package agentauthority

import (
	"os"
	"syscall"
)

// launchable reports whether the user who owns home could execute a file
// with info's mode. The daemon may run as root, so its own access proves
// nothing: the owner's execute bit counts when that user owns the file, and
// otherwise a group or other bit (group membership isn't read, so a group
// bit is taken as possible).
func launchable(home string, info os.FileInfo) bool {
	perm := info.Mode().Perm()
	file, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return perm&0o111 != 0
	}
	homeInfo, err := os.Stat(home)
	if err != nil {
		return perm&0o111 != 0
	}
	user, ok := homeInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return perm&0o111 != 0
	}
	if file.Uid == user.Uid {
		return perm&0o100 != 0
	}
	return perm&0o011 != 0
}
