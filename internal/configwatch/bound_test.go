package configwatch

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/privacyfolder"
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

// eventBackend is a countingBackend whose events the test sends.
type eventBackend struct {
	countingBackend
	events chan []event
}

func (b *eventBackend) wait(timeout time.Duration) ([]event, error) {
	select {
	case events := <-b.events:
		return events, nil
	case <-time.After(timeout):
		return nil, nil
	}
}

// handleFor returns the open handle for path.
func (b *eventBackend) handleFor(path string) (int, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for handle, open := range b.open {
		if open == path {
			return handle, true
		}
	}
	return 0, false
}

// A watched project folder replaced by a link into a privacy folder is
// refused before anything is read through the link: the renewal after the
// old watch goes checks the path first, so lstat never follows the linked
// parent into the protected folder.
func TestALinkIntoAPrivacyFolderIsNeverRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		// As in privacyfolder's own TestGuarded: the guard is macOS's and
		// reads paths as /-separated, so Windows paths do not fit it.
		t.Skip("the macOS privacy-folder guard does not read Windows paths")
	}
	saved := waitSlice
	waitSlice = 5 * time.Millisecond
	t.Cleanup(func() { waitSlice = saved })
	enabled := privacyfolder.Enabled
	privacyfolder.Enabled = true
	t.Cleanup(func() { privacyfolder.Enabled = enabled })
	home := t.TempDir()
	code := filepath.Join(home, "code")
	settings := filepath.Join(code, "app", ".claude", "settings.json")
	protected := filepath.Join(home, "Documents", "app", ".claude", "settings.json")
	for _, path := range []string{settings, protected} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	var throughLink []string
	savedLstat := lstat
	lstat = func(path string) (os.FileInfo, error) {
		if info, err := os.Lstat(code); err == nil && info.Mode()&os.ModeSymlink != 0 &&
			strings.HasPrefix(path, code+string(filepath.Separator)) {
			mu.Lock()
			throughLink = append(throughLink, path)
			mu.Unlock()
		}
		return os.Lstat(path)
	}
	t.Cleanup(func() { lstat = savedLstat })

	b := &eventBackend{countingBackend: countingBackend{open: map[int]string{}}, events: make(chan []event)}
	w := &Watcher{changed: func() {}, opts: Options{Home: home, Delay: time.Second, MinGap: time.Second}, next: make(chan []string, 1), done: make(chan struct{}), stopped: make(chan struct{})}
	go w.run(b)
	t.Cleanup(w.Close)
	w.Set([]string{settings})
	deadline := time.Now().Add(3 * time.Second)
	handle, ok := b.handleFor(settings)
	for !ok {
		if time.Now().After(deadline) {
			t.Fatal("the settings file was never watched")
		}
		time.Sleep(5 * time.Millisecond)
		handle, ok = b.handleFor(settings)
	}

	// The fake backend sends nothing on its own, so the swap is complete
	// before the watcher looks again.
	if err := os.RemoveAll(code); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "Documents"), code); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	opened := b.next
	b.mu.Unlock()
	b.events <- []event{{handle: handle, gone: true}}
	// A second send returns once the first batch, and its renewal, is done.
	b.events <- nil

	mu.Lock()
	defer mu.Unlock()
	if len(throughLink) > 0 {
		t.Fatalf("lstat read through the link into a privacy folder: %v", throughLink)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.next != opened {
		t.Fatalf("%d watches opened through the link: %v", b.next-opened, b.open)
	}
}
