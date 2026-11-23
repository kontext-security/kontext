//go:build darwin || linux

package configwatch

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	waitSlice = 10 * time.Millisecond
	os.Exit(m.Run())
}

func newTestWatcher(t *testing.T, home string) (*Watcher, <-chan struct{}) {
	t.Helper()
	fired := make(chan struct{}, 16)
	w := New(func() { fired <- struct{}{} }, Options{Home: home, Delay: 20 * time.Millisecond, MinGap: 20 * time.Millisecond})
	t.Cleanup(w.Close)
	return w, fired
}

func expectFire(t *testing.T, fired <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s: no change reported", what)
	}
}

func drain(fired <-chan struct{}) {
	time.Sleep(150 * time.Millisecond)
	for {
		select {
		case <-fired:
		default:
			return
		}
	}
}

// settle lets the watcher take a new set before the test changes files.
func settle() { time.Sleep(100 * time.Millisecond) }

// registered waits for the scan that new watches ask for, then clears it,
// so the change a test makes next has to wake the scan through its own
// file event.
func registered(t *testing.T, fired <-chan struct{}) {
	t.Helper()
	expectFire(t, fired, "new watches")
	drain(fired)
}

func TestChangesWakeTheScan(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".claude")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(settings, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w, fired := newTestWatcher(t, home)
	w.Set([]string{settings})
	registered(t, fired)

	if err := os.WriteFile(settings, []byte(`{"hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	expectFire(t, fired, "in-place write")
	drain(fired)

	// An editor's atomic save: write beside, rename over.
	tmp := filepath.Join(dir, ".settings.json.tmp")
	if err := os.WriteFile(tmp, []byte(`{"hooks":{"Stop":[]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, settings); err != nil {
		t.Fatal(err)
	}
	expectFire(t, fired, "atomic replace")
	drain(fired)

	// The replaced file is watched again, not the old one.
	if err := os.WriteFile(settings, []byte(`{"hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	expectFire(t, fired, "write after replace")
	drain(fired)

	if err := os.Remove(settings); err != nil {
		t.Fatal(err)
	}
	expectFire(t, fired, "delete")
	drain(fired)

	// A missing file shows when it is created, through its folder.
	if err := os.WriteFile(settings, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	expectFire(t, fired, "create")
}

func TestBurstsAreSpaced(t *testing.T) {
	home := t.TempDir()
	file := filepath.Join(home, "sub", "a.json")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	fired := make(chan struct{}, 64)
	const gap = time.Second
	w := New(func() { fired <- struct{}{} }, Options{Home: home, Delay: 20 * time.Millisecond, MinGap: gap})
	t.Cleanup(w.Close)
	w.Set([]string{file})
	// The scan new watches ask for opens a gap of its own; let it close so
	// the burst below is what wakes the scan.
	expectFire(t, fired, "new watches")
	time.Sleep(gap + 200*time.Millisecond)
	if n := len(fired); n != 0 {
		t.Fatalf("new watches woke the scan %d more times", n)
	}
	for i := range 20 {
		if err := os.WriteFile(file, []byte{byte(i)}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	expectFire(t, fired, "burst")
	time.Sleep(300 * time.Millisecond)
	if n := len(fired); n != 0 {
		t.Fatalf("burst woke the scan %d more times inside the gap", n)
	}
}

func TestEmptySetStopsWatching(t *testing.T) {
	home := t.TempDir()
	file := filepath.Join(home, "sub", "a.json")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	w, fired := newTestWatcher(t, home)
	w.Set([]string{file})
	// New watches ask for one scan of their own; let it pass.
	drain(fired)
	w.Set(nil)
	settle()
	if err := os.WriteFile(file, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fired:
		t.Fatal("a released watch still woke the scan")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestTargetsSkipHomeAndClimb(t *testing.T) {
	home := "/Users/someone"
	got := Targets(home, []string{"/Users/someone/.claude.json", "relative/path", "/Users/someone/code/app/.claude/settings.json", "/Users/someone/code/app/.claude/settings.json"})
	want := []Target{
		{Path: "/Users/someone/.claude.json"},
		{Path: "/Users/someone/code/app/.claude/settings.json"},
		// The settings folder, or the project and its parent while the
		// folder is missing; never the home folder.
		{Path: "/Users/someone/code/app/.claude", Fallbacks: []string{"/Users/someone/code/app", "/Users/someone/code"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Targets = %+v, want %+v", got, want)
	}
}

// A project with no .claude folder yet is watched at its own folder, so the
// first settings file created there wakes the scan.
func TestFirstProjectSettingsWakeTheScan(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "code", "app")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(project, ".claude", "settings.json")
	w, fired := newTestWatcher(t, home)
	w.Set([]string{settings})
	registered(t, fired)
	if err := os.Mkdir(filepath.Join(project, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	expectFire(t, fired, "settings folder created")
	drain(fired)
	// The next scan's set watches the new folder itself.
	w.Set([]string{settings})
	registered(t, fired)
	if err := os.WriteFile(settings, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	expectFire(t, fired, "first settings file")
}

func TestCloseIsIdempotent(t *testing.T) {
	w := New(func() {}, Options{})
	w.Close()
	w.Close()
	w.Set([]string{"/tmp"})
	var none *Watcher
	none.Set(nil)
	none.Close()
}

// A scan's read and the watch placed after it leave a gap a write can fall
// into, so new watches ask for one more scan, and the same set again asks
// for none.
func TestNewWatchesAskForOneScan(t *testing.T) {
	home := t.TempDir()
	file := filepath.Join(home, "sub", "settings.json")
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w, fired := newTestWatcher(t, home)
	w.Set([]string{file})
	expectFire(t, fired, "new watches")
	drain(fired)
	w.Set([]string{file})
	select {
	case <-fired:
		t.Fatal("the same set asked for another scan")
	case <-time.After(300 * time.Millisecond):
	}
}

// A log appended next to a watched file is not a hook change: only the
// watched file's own writes, or entries added or removed, wake the scan.
func TestSiblingWritesDoNotWakeTheScan(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "sub")
	file := filepath.Join(dir, "settings.json")
	log := filepath.Join(dir, "history.jsonl")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, log} {
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w, fired := newTestWatcher(t, home)
	w.Set([]string{file})
	drain(fired)
	f, err := os.OpenFile(log, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	select {
	case <-fired:
		t.Fatal("a write to an unwatched sibling woke the scan")
	case <-time.After(300 * time.Millisecond):
	}
	if err := os.WriteFile(file, []byte(`{"hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	expectFire(t, fired, "watched file write")
}
