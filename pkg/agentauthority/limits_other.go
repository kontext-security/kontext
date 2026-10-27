//go:build !unix

package agentauthority

import (
	"context"
	"os"
)

// readGuarded refuses every content read (read, list, tail, cursor) where the unix walk does not
// exist: Windows, and any other non-unix target. The unix walk opens each component with
// O_NOFOLLOW from the parent's descriptor and checks that the file it read is the one it checked;
// Windows needs its own walk with the same guarantees (no reparse points, no placeholder
// hydration). Until then the scan reads no file content there. A stat-only check does not come
// here: access answers it from guardedInfo's walk, which starts at the drive or UNC share and
// refuses a junction (reported as irregular) or a placeholder ancestor.
func readGuarded(context.Context, string, string) fileResult {
	return fileResult{err: os.ErrPermission}
}

// isEvictedErr has no equivalent here yet: on Windows placeholders are refused before any read.
func isEvictedErr(error) bool { return false }
