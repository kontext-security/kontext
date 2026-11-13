//go:build !unix && !windows

package agentauthority

import (
	"context"
	"os"
)

// readGuarded refuses every content read (read, list, tail, cursor) on a target that has no
// guarded walk of its own. Unix opens each component with O_NOFOLLOW from the parent's
// descriptor (limits_unix.go) and Windows each by its name from the parent's handle
// (limits_windows.go); anything else reads no file content. A stat-only check does not come
// here: access answers it from guardedInfo's walk.
func readGuarded(context.Context, string, string) fileResult {
	return fileResult{err: os.ErrPermission}
}

// statGuarded says what a path is by lstat, component by component.
func statGuarded(_ context.Context, path, mode string) (os.FileInfo, error) {
	return guardedInfo(path, os.Lstat, mode == "tail" || mode == "cursor")
}

// readable never runs here: with no content reads, nothing is cached.
func readable(string, string) error { return nil }

// isEvictedErr has no equivalent here: nothing is read.
func isEvictedErr(error) bool { return false }
