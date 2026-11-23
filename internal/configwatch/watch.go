// Package configwatch tells the daemon soon after an agent's configuration
// changes on disk, so a hook added, edited or removed shows within seconds
// rather than at the next poll (ENG-1105).
//
// It watches the files a scan read and the folders that hold them: an
// in-place write changes the file, and an atomic replace or a delete changes
// its folder. Notifications are a hint only. A missed one waits for the
// caller's poll, which stays the source of truth.
package configwatch

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// MaxTargets bounds the files and folders watched at once. Each one costs a
// descriptor on macOS; past the bound the poll covers the rest.
const MaxTargets = 256

const (
	// DefaultDelay gathers a burst of writes (an editor's save, a plugin
	// install) into one rescan.
	DefaultDelay = time.Second
	// DefaultMinGap spaces rescans while a file keeps changing, such as
	// ~/.claude.json, which Claude Code rewrites as it runs.
	DefaultMinGap = 10 * time.Second
)

// waitSlice is how long the watcher waits for events before it looks for a
// new set or a close. Tests shorten it.
// lstat reads what a path is before it is watched; tests replace it.
var lstat = os.Lstat

var waitSlice = 500 * time.Millisecond

// event is one notification: the target it came from, and whether that
// target is gone (deleted or renamed away), so its watch must be renewed.
type event struct {
	handle int
	gone   bool
}

// overflow is the handle of an event that stands for lost events.
const overflow = -1

// backend is the platform's notification API.
type backend interface {
	// add watches one path. A path that does not exist is an error.
	add(path string) (int, error)
	remove(handle int)
	// wait returns the events that arrive within timeout.
	wait(timeout time.Duration) ([]event, error)
	close() error
}

// Options tune a Watcher. Zero values take the defaults.
type Options struct {
	// Home is the user's home folder. It is never watched itself, since
	// every file created there would wake the scan, and no path inside a
	// privacy-guarded folder is watched.
	Home   string
	Delay  time.Duration
	MinGap time.Duration
}

// Watcher calls changed, at most once per MinGap, after a watched file or
// folder changes. Its methods are safe to call from any goroutine.
type Watcher struct {
	changed func()
	opts    Options
	next    chan []string
	done    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

// New starts a watcher. It watches nothing until Set. On a platform without
// a supported API, or when the API can't be opened, it never calls changed
// and the caller's poll does all the work.
func New(changed func(), opts Options) *Watcher {
	if opts.Delay <= 0 {
		opts.Delay = DefaultDelay
	}
	if opts.MinGap <= 0 {
		opts.MinGap = DefaultMinGap
	}
	w := &Watcher{changed: changed, opts: opts, next: make(chan []string, 1), done: make(chan struct{}), stopped: make(chan struct{})}
	b, err := newBackend()
	if err != nil {
		close(w.stopped)
		return w
	}
	go w.run(b)
	return w
}

// Set replaces what is watched with paths and the folders that hold them.
// Only the latest set counts, so a slow watcher never queues old ones.
func (w *Watcher) Set(paths []string) {
	if w == nil {
		return
	}
	paths = append([]string(nil), paths...)
	for {
		select {
		case <-w.stopped:
			return
		case w.next <- paths:
			return
		default:
		}
		select {
		case <-w.next:
		default:
		}
	}
}

// closeWait bounds Close: a watcher stuck on an unresponsive disk must not
// hold the daemon's shutdown. Its goroutine then ends when the disk answers.
const closeWait = 2 * time.Second

// Close stops the watcher and releases what it holds, waiting at most
// closeWait.
func (w *Watcher) Close() {
	if w == nil {
		return
	}
	w.once.Do(func() { close(w.done) })
	select {
	case <-w.stopped:
	case <-time.After(closeWait):
	}
}

// maxClimb is how many folders above a missing one are tried: a project
// with no .claude folder yet is watched at the project's own folder, so the
// first settings file created there shows.
const maxClimb = 2

// Target is one thing a path set asks to watch: Path, or, while Path is
// missing, the first of Fallbacks that exists.
type Target struct {
	Path      string
	Fallbacks []string
}

// Targets is what a path set watches: each path, and the folder that holds
// it, falling back to the nearest existing folder above when that one is
// missing. The home folder, the root and privacy folders are never watched.
// The result keeps the paths' order, so the first paths win the bound, and
// has no duplicates.
func Targets(home string, paths []string) []Target {
	home = filepath.Clean(home)
	seen := map[string]bool{}
	allowed := func(path string) bool {
		return path != home && path != "/" && path != "." && !privacyfolder.Guarded(home, path)
	}
	var out []Target
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			continue
		}
		path = filepath.Clean(path)
		if !seen[path] && allowed(path) {
			seen[path] = true
			out = append(out, Target{Path: path})
		}
		dir := filepath.Dir(path)
		if seen[dir] || !allowed(dir) {
			continue
		}
		seen[dir] = true
		target := Target{Path: dir}
		for up, i := filepath.Dir(dir), 0; i < maxClimb && allowed(up); up, i = filepath.Dir(up), i+1 {
			target.Fallbacks = append(target.Fallbacks, up)
		}
		out = append(out, target)
	}
	return out
}

func (w *Watcher) run(b backend) {
	defer close(w.stopped)
	watched := map[string]int{}
	paths := map[int]string{}
	defer func() {
		// Each target's own descriptor too, not only the queue's.
		for _, handle := range watched {
			b.remove(handle)
		}
		_ = b.close()
	}()
	// watch watches path, reporting whether it is watched now and whether
	// it is missing.
	added := 0
	watch := func(path string) (ok, missing bool) {
		if _, ok := watched[path]; ok {
			return true, false
		}
		if len(watched) >= MaxTargets {
			// The bound holds for open handles, not only chosen ones.
			return false, false
		}
		// Checked again at every registration, not only when the set
		// arrived: a watched folder replaced by a link into a privacy
		// folder is refused like the scan refuses it, and never opened.
		// Guarded goes first: it resolves links one part at a time and
		// stops before a protected folder, where lstat would follow a
		// linked parent into it.
		if privacyfolder.Guarded(w.opts.Home, path) {
			return false, false
		}
		info, err := lstat(path)
		if err != nil {
			return false, errors.Is(err, fs.ErrNotExist)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return false, false
		}
		handle, err := b.add(path)
		if err != nil {
			return false, errors.Is(err, fs.ErrNotExist)
		}
		if _, dup := paths[handle]; dup {
			// Another spelling of a watched file (inotify keys watches by
			// inode); the first one covers it.
			return true, false
		}
		watched[path] = handle
		paths[handle] = path
		added++
		return true, false
	}
	release := func(keep func(string) bool) (freed bool) {
		for path, handle := range watched {
			if !keep(path) {
				b.remove(handle)
				delete(watched, path)
				delete(paths, handle)
				freed = true
			}
		}
		return freed
	}
	// pick watches the first existing candidate of each target, up to the
	// bound.
	pick := func(targets []Target) map[string]bool {
		chosen := map[string]bool{}
		for _, target := range targets {
			if len(chosen) >= MaxTargets {
				break
			}
			for _, path := range append([]string{target.Path}, target.Fallbacks...) {
				ok, missing := watch(path)
				if ok {
					chosen[path] = true
				}
				if ok || !missing {
					break
				}
			}
		}
		return chosen
	}
	apply := func(targets []Target) {
		// Release what the new set can't use before opening anything, so
		// a replaced set never holds both.
		wanted := map[string]bool{}
		for _, target := range targets {
			wanted[target.Path] = true
			for _, path := range target.Fallbacks {
				wanted[path] = true
			}
		}
		release(func(path string) bool { return wanted[path] })
		chosen := pick(targets)
		// A kept fallback whose own path is back can hold a slot the bound
		// refused another target; once released, pick again.
		if release(func(path string) bool { return chosen[path] }) && len(chosen) < MaxTargets {
			chosen = pick(targets)
			release(func(path string) bool { return chosen[path] })
		}
	}
	var last []Target
	var due time.Time
	var fired time.Time
	for {
		select {
		case <-w.done:
			return
		case set := <-w.next:
			last = Targets(w.opts.Home, set)
			added = 0
			apply(last)
			if added > 0 && due.IsZero() {
				// A write between the scan's read and this watch sent no
				// event: one more scan reads what the new watches missed.
				// It names the same paths, so it adds none and stops here.
				due = time.Now().Add(w.opts.Delay)
				if gap := fired.Add(w.opts.MinGap); due.Before(gap) {
					due = gap
				}
			}
		default:
		}
		timeout := waitSlice
		if !due.IsZero() {
			if left := time.Until(due); left < timeout {
				timeout = max(left, 0)
			}
		}
		events, err := b.wait(timeout)
		if err != nil {
			return
		}
		renew, changed := false, false
		for _, e := range events {
			_, known := paths[e.handle]
			// A watch just released still reports its removal; only
			// targets watched now, or lost events, count.
			changed = changed || known || e.handle == overflow
			if e.gone {
				// The file was replaced or deleted: drop the stale watch
				// and watch whatever now has its name.
				if path, ok := paths[e.handle]; ok {
					b.remove(e.handle)
					delete(watched, path)
					delete(paths, e.handle)
					renew = true
				}
			}
		}
		if renew {
			apply(last)
		}
		now := time.Now()
		if changed && due.IsZero() {
			due = now.Add(w.opts.Delay)
			if gap := fired.Add(w.opts.MinGap); due.Before(gap) {
				due = gap
			}
		}
		if !due.IsZero() && !now.Before(due) {
			due, fired = time.Time{}, now
			w.changed()
		}
	}
}
