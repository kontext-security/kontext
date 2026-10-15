//go:build unix

package agentauthority

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// isEvictedErr reports a read refused because the file's content is not on disk. On darwin the
// scan turns dataless materialisation off (TN3150), so such a read fails with EDEADLK instead of
// downloading the file.
func isEvictedErr(err error) bool { return errors.Is(err, unix.EDEADLK) }

func readGuarded(ctx context.Context, path, mode string) (result fileResult) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		result.err = err
		return
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	prefix := "/"
	for i, part := range parts {
		prefix = filepath.Join(prefix, part)
		info, statErr := os.Lstat(prefix)
		if statErr != nil {
			unix.Close(fd)
			result.err = statErr
			return
		}
		if info.Mode()&os.ModeSymlink != 0 || isDataless(info) || (!info.IsDir() && !info.Mode().IsRegular()) || mode != "tail" && mode != "cursor" && !info.IsDir() && info.Size() > maxFileBytes {
			unix.Close(fd)
			result.err = os.ErrPermission
			return
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 || info.IsDir() {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(fd, part, flags, 0)
		unix.Close(fd)
		if openErr != nil {
			result.err = openErr
			return
		}
		fd = next
		if i == len(parts)-1 {
			result.info = info
		}
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	// Only opened regular files spend the file budget, not directory traversal
	// or Lstat calls (including probes for files that do not exist).
	result.opened = result.info.Mode().IsRegular()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(result.info, actual) {
		result.err = os.ErrPermission
		return
	}
	result.info = actual
	switch mode {
	case "cursor":
		if !actual.Mode().IsRegular() {
			result.err = os.ErrPermission
			return
		}
		value, err := readCursor(ctx, file)
		result.parsed = value
		if err != nil {
			result.parseErr = errParse
		}
	case "stat":
		if !actual.Mode().IsRegular() {
			result.err = os.ErrPermission
		}
	case "read":
		if !actual.Mode().IsRegular() || actual.Size() > maxFileBytes {
			result.err = os.ErrPermission
			return
		}
		result.data, result.err = io.ReadAll(io.LimitReader(file, maxFileBytes+1))
		if len(result.data) > maxFileBytes {
			result.data = nil
			result.err = os.ErrPermission
		}
	case "tail":
		if !actual.Mode().IsRegular() {
			result.err = os.ErrPermission
			return
		}
		const tailBytes = 8 * 1024 * 1024
		_, result.err = file.Seek(max(0, actual.Size()-tailBytes), io.SeekStart)
		if result.err == nil {
			result.data, result.err = io.ReadAll(io.LimitReader(file, tailBytes))
		}
	case "list":
		result.entries, result.err = file.ReadDir(maxFiles + 1)
		if result.err == io.EOF {
			result.err = nil
		}
	}
	return
}
