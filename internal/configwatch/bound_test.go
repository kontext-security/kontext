package configwatch

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// countingBackend accepts every path and records the most handles open at
// once.
type countingBackend struct {
	mu      sync.Mutex
	next    int
	open    map[int]bool
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
	b.open[b.next] = true
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

// Replacing one full set with another never holds more than the bound.
func TestReplacingASetStaysWithinTheBound(t *testing.T) {
	saved := waitSlice
	waitSlice = 5 * time.Millisecond
	t.Cleanup(func() { waitSlice = saved })
	// A real folder, so the paths are absolute on every platform.
	home := t.TempDir()
	b := &countingBackend{open: map[int]bool{}}
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
	settled := func(want int) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			if open, _ := b.counts(); open == want {
				return
			}
			if time.Now().After(deadline) {
				open, _ := b.counts()
				t.Fatalf("open handles: got %d, want %d", open, want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	w.Set(set("a"))
	settled(MaxTargets)
	w.Set(set("b"))
	time.Sleep(50 * time.Millisecond)
	settled(MaxTargets)
	if _, peak := b.counts(); peak > MaxTargets {
		t.Fatalf("peak open handles %d, over the bound %d", peak, MaxTargets)
	}
}
