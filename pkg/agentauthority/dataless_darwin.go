//go:build darwin

package agentauthority

import (
	"golang.org/x/sys/unix"
	"os"
	"syscall"
)

func isDataless(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && (stat.Flags&unix.SF_DATALESS != 0 || info.Mode().IsRegular() && stat.Size > 0 && stat.Blocks == 0)
}
