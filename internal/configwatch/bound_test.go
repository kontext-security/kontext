package configwatch

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// countingBackend accepts every path and records the most handles open at
// once.
type countingBackend struct {
	mu      sync.Mutex
	next    int
	open    map[int]string
	peak    int
	missing map[string]bool
}

func (b *countingBackend) add(path string) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.missing[path] {
		return 0, fs.ErrNotExist
	}
	b.next++
	b.open[b.next] = path
	b.peak = max(b.peak, len(b.open))
	return b.next, nil
}

func (b *countingBackend) remove(handle int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.open, handle)
}

func (b *countingBackend) wait(timeout time.Duration) ([]event, error) {
	time.Sleep(timeout)
	return nil, nil
}

func (b *countingBackend) close() error { return nil }

func (b *countingBackend) counts() (open, peak int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.open), b.peak
}

// holds reports whether every open handle is for a path under prefix.
func (b *countingBackend) holds(prefix string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, path := range b.open {
		if !strings.HasPrefix(path, prefix) {
			return false
		}
	}
	return len(b.open) > 0
}

// pretendEveryPathExists stands in for lstat, so a fake backend can watch
// paths that are not on disk.
func pretendEveryPathExists(t *testing.T) {
	t.Helper()
	dir, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	saved := lstat
	lstat = func(string) (os.FileInfo, error) { return dir, nil }
	t.Cleanup(func() { lstat = saved })
}

// Replacing one full set with another never holds more than the bound.
func TestReplacingASetStaysWithinTheBound(t *testing.T) {
	saved := waitSlice
	waitSlice = 5 * time.Millisecond
	t.Cleanup(func() { waitSlice = saved })
	// A real folder, so the paths are absolute on every platform.
	home := t.TempDir()
	pretendEveryPathExists(t)
	b := &countingBackend{open: map[int]string{}}
	w := &Watcher{changed: func() {}, opts: Options{Home: home, Delay: time.Second, MinGap: time.Second}, next: make(chan []string, 1), done: make(chan struct{}), stopped: make(chan struct{})}
	go w.run(b)
	t.Cleanup(w.Close)
	set := func(prefix string) []string {
		var paths []string
		for i := range MaxTargets {
			paths = append(paths, filepath.Join(home, fmt.Sprintf("%s%d", prefix, i), ".claude", "settings.json"))
		}
		return paths
	}
	// settled waits until the set under prefix is the one in place.
	settled := func(prefix string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			if open, _ := b.counts(); open == MaxTargets && b.holds(prefix) {
				return
			}
			if time.Now().After(deadline) {
				open, _ := b.counts()
				t.Fatalf("open handles: got %d, want %d under %s", open, MaxTargets, prefix)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	w.Set(set("a"))
	settled(filepath.Join(home, "a"))
	w.Set(set("b"))
	settled(filepath.Join(home, "b"))
	if _, peak := b.counts(); peak > MaxTargets {
		t.Fatalf("peak open handles %d, over the bound %d", peak, MaxTargets)
	}
}

// A link is never watched, even when it was a plain folder when the set
// arrived: the check runs at every registration, like the scan's.
func TestLinksAreNeverWatched(t *testing.T) {
	saved := waitSlice
	waitSlice = 5 * time.Millisecond
	t.Cleanup(func() { waitSlice = saved })
	home := t.TempDir()
	target := filepath.Join(home, "elsewhere")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "project", ".claude")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	b := &countingBackend{open: map[int]string{}}
	w := &Watcher{changed: func() {}, opts: Options{Home: home, Delay: time.Second, MinGap: time.Second}, next: make(chan []string, 1), done: make(chan struct{}), stopped: make(chan struct{})}
	go w.run(b)
	t.Cleanup(w.Close)
	w.Set([]string{link})
	deadline := time.Now().Add(3 * time.Second)
	for {
		// The link's own folder is a plain one and is watched.
		if open, _ := b.counts(); open > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("nothing was watched")
		}
		time.Sleep(5 * time.Millisecond)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, path := range b.open {
		if path == link {
			t.Fatalf("watched the link %s", link)
		}
	}
}
