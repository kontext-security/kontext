package agentauthority

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const maxFiles = 500
const maxFileBytes = 1024 * 1024
const maxReportBytes = 64 * 1024
const managedRoot = "/Library/Application Support/ClaudeCode"

// Each root is resolved relative to home once, never from configuration contents.
// Custom discovery paths do not expand this allowlist; explicit environment
// overrides add only their named configuration files inside home.
func allowedRoots(home, managed string) []string {
	roots := []string{managed}
	for _, root := range []string{".openclaw", ".clawdbot", ".qwen", ".config/goose", ".factory", ".config/devin", ".pi/agent", ".kimi", ".kimi-code", ".augment", ".config/kilo", ".config/crush", ".junie", ".grok", ".hermes", ".cline/data/settings/cline_mcp_settings.json", ".claude.json", ".claude", ".codex", ".cursor", ".cline/data/globalState.json", "Library/Application Support/Cursor/User/globalStorage/state.vscdb", "Library/Application Support/Windsurf/User/settings.json", ".codeium/windsurf", ".copilot", ".gemini", ".kiro", ".config/amp", ".config/opencode", ".config/gh", ".config/gcloud", ".aws", ".kube", ".ssh", ".npmrc", ".docker/config.json", "Library/Application Support/Claude", "Library/Application Support/Code/User/mcp.json"} {
		roots = append(roots, filepath.Join(home, root))
	}
	return roots
}

type guard struct {
	ctx           context.Context
	home, managed string
	roots         []string
	opened        int
	report        *Report
	readFile      func(string, string) fileResult
	lstat         func(string) (os.FileInfo, error)
	cache         map[string]fileResult
	beginRead     func() func()
	seen          map[string]bool
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
	data     []byte
	entries  []os.DirEntry
	info     os.FileInfo
	walInfo  os.FileInfo
	err      error
	opened   bool
	parsed   any
	parseErr error
}

// One per-file budget includes metadata, ancestor checks, open, and read.
// A timed-out worker finishes and closes its own file without blocking later reads.
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
	for _, root := range []string{filepath.Join(g.home, "Desktop"), filepath.Join(g.home, "Documents"), filepath.Join(g.home, "Downloads"), filepath.Join(g.home, "Library/Mobile Documents"), filepath.Join(g.home, "Library/CloudStorage"), "/Volumes"} {
		if within(root, path) {
			g.skip()
			return fileResult{err: os.ErrPermission}
		}
	}
	readCtx, cancel := context.WithTimeout(g.ctx, time.Second)
	defer cancel()
	done := make(chan fileResult, 1)
	read := g.readFile
	if read == nil {
		read = func(path, mode string) fileResult { return readGuarded(readCtx, path, mode) }
	}
	stat := g.lstat
	if stat == nil {
		stat = os.Lstat
	}
	if g.seen != nil {
		g.seen[path] = true
	}
	cached, hasCache := g.cache[path]
	beginRead := g.beginRead
	go func() {
		if beginRead != nil {
			defer beginRead()()
		}
		info, err := guardedInfo(path, stat, mode == "tail" || mode == "cursor")
		if err != nil {
			done <- fileResult{err: err}
			return
		}
		var walInfo os.FileInfo
		if mode == "cursor" {
			walInfo, err = guardedInfo(path+"-wal", stat, true)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				done <- fileResult{err: err}
				return
			}
		}
		if mode == "stat" {
			if !info.Mode().IsRegular() {
				done <- fileResult{err: os.ErrPermission}
				return
			}
			done <- fileResult{info: info}
			return
		}
		if hasCache && sameFileVersion(cached.info, info) && sameFileVersion(cached.walInfo, walInfo) {
			cached.opened = false
			done <- cached
			return
		}
		result := read(path, mode)
		// Keep the pre-query WAL version: a commit during the query invalidates the
		// next scan instead of caching an older value against newer metadata.
		result.walInfo = walInfo
		done <- result
	}()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case result := <-done:
		if result.opened {
			g.opened++
		}
		if result.err != nil && !errors.Is(result.err, os.ErrNotExist) {
			g.skip()
		}
		if result.err == nil && g.cache != nil && mode != "stat" {
			g.cache[path] = result
		} else if result.err != nil && g.cache != nil {
			delete(g.cache, path)
		}
		if errors.Is(result.err, unix.EDEADLK) {
			g.readError(path, "evicted, skipped")
		}
		return result
	case <-g.ctx.Done():
		g.report.Truncated = true
		g.skip()
		return fileResult{err: g.ctx.Err()}
	case <-timer.C:
		g.skip()
		g.readError(path, "read timeout")
		return fileResult{err: context.DeadlineExceeded}
	}
}

func (g *guard) readError(path, reason string) {
	if len(g.report.Coverage.Errors) < 200 {
		source := safe(g.source(path), 200)
		if source == "" || secret(source, "errors") {
			source = "<redacted>"
		}
		message := reason + ": " + source
		if !slices.Contains(g.report.Coverage.Errors, message) {
			g.report.Coverage.Errors = append(g.report.Coverage.Errors, message)
		}
	}
}

// Check every ancestor before opening anything, including dataless directories.
func guardedInfo(path string, stat func(string) (os.FileInfo, error), tail bool) (os.FileInfo, error) {
	prefix := "/"
	var info os.FileInfo
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		prefix = filepath.Join(prefix, part)
		var err error
		info, err = stat(prefix)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) || isDataless(info) || (!tail && !info.IsDir() && info.Size() > maxFileBytes) {
			return nil, os.ErrPermission
		}
	}
	return info, nil
}

func sameFileVersion(a, b os.FileInfo) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

var errParse = errors.New("configuration parse error")

// Cache parsed values, never raw file contents (which can contain credentials).
func readParsed[T any](g *guard, path string, parse func([]byte) (T, error), modes ...string) (T, error) {
	mode := "read"
	if len(modes) > 0 {
		mode = modes[0]
	}
	result := g.access(path, mode)
	if result.err != nil {
		var zero T
		return zero, result.err
	}
	if parsed, ok := result.parsed.(T); ok {
		return parsed, result.parseErr
	}
	value, err := parse(result.data)
	if err != nil {
		err = errors.Join(errParse, err)
	}
	if g.cache != nil {
		result.data, result.parsed, result.parseErr = nil, value, err
		g.cache[filepath.Clean(path)] = result
	}
	return value, err
}

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
		const tailBytes = 64 * 1024
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
		g.report.Coverage.Limits = append(g.report.Coverage.Limits, "directory entries limited to 500")
		g.skip()
		result.entries = result.entries[:maxFiles]
	}
	sort.Slice(result.entries, func(i, j int) bool { return result.entries[i].Name() < result.entries[j].Name() })
	return result.entries
}

func readConfig[T any](g *guard, id, path string, parse func([]byte) (T, error), modes ...string) (T, bool) {
	value, err := readParsed(g, path, parse, modes...)
	if errors.Is(err, errParse) {
		g.parseError(id, filepath.Base(path))
	}
	return value, err == nil
}
func parseJSON[T any](data []byte) (T, error) {
	var value T
	err := json.Unmarshal(data, &value)
	return value, err
}

// CoworkVMLogTail reads only the last 64 KB of the fixed Cowork VM log, through
// the same deadline, no-symlink and dataless guard as configuration reads.
func CoworkVMLogTail(ctx context.Context, home string) ([]byte, error) {
	path := filepath.Join(home, "Library/Logs/Claude/cowork_vm_swift.log")
	g := guard{ctx: ctx, home: home, roots: []string{path}, report: &Report{}}
	result := g.access(path, "tail")
	return result.data, result.err
}
