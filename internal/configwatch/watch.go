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

// Close stops the watcher and releases what it holds.
func (w *Watcher) Close() {
	if w == nil {
		return
	}
	w.once.Do(func() { close(w.done) })
	<-w.stopped
}

// Targets is what a path set watches: each path, and the folder that holds
// it unless that folder is the home folder or the root. Paths in a privacy
// folder are left out. The result keeps the paths' order, so the first
// paths win the bound, has no duplicates, and is at most MaxTargets long.
func Targets(home string, paths []string) []string {
	home = filepath.Clean(home)
	seen := map[string]bool{}
	var out []string
	keep := func(path string) {
		if seen[path] || path == home || path == "/" || path == "." {
			return
		}
		seen[path] = true
		if privacyfolder.Guarded(home, path) {
			return
		}
		out = append(out, path)
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			continue
		}
		path = filepath.Clean(path)
		keep(path)
		keep(filepath.Dir(path))
	}
	if len(out) > MaxTargets {
		out = out[:MaxTargets]
	}
	return out
}

func (w *Watcher) run(b backend) {
	defer close(w.stopped)
	defer b.close()
	watched := map[string]int{}
	paths := map[int]string{}
	apply := func(targets []string) {
		want := map[string]bool{}
		for _, target := range targets {
			want[target] = true
		}
		for path, handle := range watched {
			if !want[path] {
				b.remove(handle)
				delete(watched, path)
				delete(paths, handle)
			}
		}
		for _, target := range targets {
			if _, ok := watched[target]; ok {
				continue
			}
			if handle, err := b.add(target); err == nil {
				if _, dup := paths[handle]; dup {
					// Another spelling of a watched file (inotify keys
					// watches by inode); the first one covers it.
					continue
				}
				watched[target] = handle
				paths[handle] = target
			}
		}
	}
	var last []string
	var due time.Time
	var fired time.Time
	for {
		select {
		case <-w.done:
			return
		case set := <-w.next:
			last = Targets(w.opts.Home, set)
			apply(last)
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
