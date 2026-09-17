//go:build !darwin

package agentauthority

import (
	"os"
	"syscall"
)

func isDataless(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && stat.Size > 0 && stat.Blocks == 0
}
