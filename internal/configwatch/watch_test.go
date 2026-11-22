//go:build darwin || linux

package configwatch

import (
	"os"
	"path/filepath"
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
	settle()

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
	w := New(func() { fired <- struct{}{} }, Options{Home: home, Delay: 20 * time.Millisecond, MinGap: time.Hour})
	t.Cleanup(w.Close)
	w.Set([]string{file})
	settle()
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
	settle()
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

func TestTargetsSkipHomeAndBound(t *testing.T) {
	home := "/Users/someone"
	got := Targets(home, []string{"/Users/someone/.claude.json", "relative/path", "/Users/someone/.claude/settings.json", "/Users/someone/.claude/settings.json"})
	want := []string{"/Users/someone/.claude.json", "/Users/someone/.claude/settings.json", "/Users/someone/.claude"}
	if len(got) != len(want) {
		t.Fatalf("Targets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Targets = %v, want %v", got, want)
		}
	}
	var many []string
	for i := range MaxTargets {
		many = append(many, filepath.Join(home, "p", string(rune('a'+i%26)), "x", "f"+string(rune('a'+i/26))))
	}
	if n := len(Targets(home, many)); n != MaxTargets {
		t.Fatalf("Targets kept %d, want the bound %d", n, MaxTargets)
	}
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
