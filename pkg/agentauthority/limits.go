package agentauthority

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const maxFiles = 2000
const maxFileBytes = 1024 * 1024
const maxReportBytes = 64 * 1024
const managedRoot = "/Library/Application Support/ClaudeCode"

type guard struct {
	ctx           context.Context
	home, managed string
	roots         []string
	opened        int
	report        *Report
	readFile      func(string, string) fileResult
	scanDetails   []func()
	scanSkills    []func()
}

func (g *guard) skip() { g.report.Coverage.SkippedFiles++ }
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func (g *guard) source(path string) string {
	if within(g.home, path) {
		rel, _ := filepath.Rel(g.home, path)
		return "~/" + filepath.ToSlash(rel)
	}
	if within(g.managed, path) {
		return "managed-settings"
	}
	return "<project>/" + filepath.Base(path)
}

type fileResult struct {
	data    []byte
	entries []os.DirEntry
	info    os.FileInfo
	err     error
	opened  bool
}

// One time budget includes metadata, ancestor checks, open, and read. A timed-out
// filesystem stops this scan, leaving at most one worker to close its own file.
func (g *guard) access(path, mode string) fileResult {
	if g.ctx.Err() != nil || g.opened >= maxFiles {
		g.report.Truncated = true
		g.skip()
		return fileResult{err: context.DeadlineExceeded}
	}
	path = filepath.Clean(path)
	allowed := false
	for _, root := range g.roots {
		if within(root, path) {
			allowed = true
			break
		}
	}
	if !allowed || !filepath.IsAbs(path) {
		g.skip()
		return fileResult{err: os.ErrPermission}
	}
	done := make(chan fileResult, 1)
	read := g.readFile
	if read == nil {
		read = readGuarded
	}
	go func() { done <- read(path, mode) }()
	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()
	select {
	case result := <-done:
		if result.opened {
			g.opened++
		}
		if result.err != nil && !errors.Is(result.err, os.ErrNotExist) {
			g.skip()
		}
		return result
	case <-g.ctx.Done():
		g.opened = maxFiles
		g.report.Truncated = true
		g.skip()
		return fileResult{err: g.ctx.Err()}
	case <-timer.C:
		g.opened = maxFiles
		g.report.Truncated = true
		g.skip()
		return fileResult{err: context.DeadlineExceeded}
	}
}
func readGuarded(path, mode string) (result fileResult) {
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
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) || !info.IsDir() && info.Size() > maxFileBytes {
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
	case "list":
		result.entries, result.err = file.ReadDir(maxFiles + 1)
		if result.err == io.EOF {
			result.err = nil
		}
	}
	return
}
func (g *guard) read(path string) []byte {
	result := g.access(path, "read")
	if result.err != nil {
		return nil
	}
	return result.data
}
func (g *guard) entries(path string) []os.DirEntry {
	result := g.access(path, "list")
	if result.err != nil {
		return nil
	}
	if len(result.entries) > maxFiles {
		g.report.Truncated = true
		g.skip()
		result.entries = result.entries[:maxFiles]
	}
	sort.Slice(result.entries, func(i, j int) bool { return result.entries[i].Name() < result.entries[j].Name() })
	return result.entries
}
