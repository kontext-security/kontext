//go:build !unix

package agentauthority

import (
	"context"
	"os"
)

// readGuarded refuses every read where the unix walk does not exist: Windows, and any other
// non-unix target. The unix walk opens each component with O_NOFOLLOW from the parent's
// descriptor and checks that the file it read is the one it checked; Windows needs its own walk
// with the same guarantees (no reparse points, no placeholder hydration). Until then the scan
// reports nothing rather than something unguarded.
func readGuarded(context.Context, string, string) fileResult {
	return fileResult{err: os.ErrPermission}
}

// isEvictedErr has no equivalent here yet: on Windows placeholders are refused before any read.
func isEvictedErr(error) bool { return false }
