package tooloutput

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hermetic"
)

const (
	day = 24 * time.Hour
	mib = 1 << 20
)

// savedDir is a save directory whose compactor reads a clock that moves
// only when a test moves it.
type savedDir struct {
	t   *testing.T
	c   *Compactor
	now time.Time
}

func newSavedDir(t *testing.T) *savedDir {
	t.Helper()
	d := &savedDir{t: t, now: time.Now()}
	d.c = New(Options{
		Dir: filepath.Join(t.TempDir(), "managed-observe", "tool-output"),
		Now: func() time.Time { return d.now },
	})
	return d
}

// save writes a file of size bytes into a session's directory, last modified
// age before the clock. The file is sparse: Prune counts its size, not the
// disk it takes.
func (d *savedDir) save(session, name string, size int64, age time.Duration) string {
	d.t.Helper()
	path := filepath.Join(d.c.dir, session, name)
	if err := writePrivate(d.c.dir, path, nil); err != nil {
		d.t.Fatal(err)
	}
	if err := os.Truncate(path, size); err != nil {
		d.t.Fatal(err)
	}
	d.age(path, age)
	return path
}

// age sets a path's modification time to age before the clock.
func (d *savedDir) age(path string, age time.Duration) {
	d.t.Helper()
	at := d.now.Add(-age)
	if err := os.Chtimes(path, at, at); err != nil {
		d.t.Fatal(err)
	}
}

// exists reports whether path is there, a link itself and not its target.
func (d *savedDir) exists(path string) bool {
	d.t.Helper()
	_, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		d.t.Fatal(err)
	}
	return err == nil
}

// A session that saved an output within Retention keeps every output it
// saved, the oldest too: its agent may still read them back. Retention after
// its newest output, the whole session goes.
func TestPruneKeepsEveryOutputOfASessionUntilRetentionAfterItsNewest(t *testing.T) {
	d := newSavedDir(t)
	session := []string{
		d.save("long", "toolu_first.txt", 4096, 30*day),
		d.save("long", "toolu_first.json", 100, 30*day),
		d.save("long", "toolu_second.txt", 4096, 8*day),
		d.save("long", "toolu_latest.txt", 4096, Retention-time.Minute),
	}
	d.c.Prune()
	for _, path := range session {
		if !d.exists(path) {
			t.Fatalf("%s deleted while its session's newest output is %v old", filepath.Base(path), Retention-time.Minute)
		}
	}

	d.now = d.now.Add(2 * time.Minute)
	d.c.Prune()
	if dir := filepath.Dir(session[0]); d.exists(dir) {
		t.Fatalf("session kept with its newest output %v old", Retention+time.Minute)
	}
}

// A quiet session goes as one directory, outputs and records alike, and the
// session that saved recently stays.
func TestPruneDeletesAQuietSessionsWholeDirectory(t *testing.T) {
	d := newSavedDir(t)
	d.save("codex-quiet", "call_a-1.txt", 4096, 20*day)
	d.save("codex-quiet", "call_a-1.json", 100, 20*day)
	d.save("codex-quiet", "call_b.txt", 4096, Retention+time.Minute)
	d.save("codex-quiet", "call_b.json", 100, Retention+time.Minute)
	active := []string{
		d.save("active", "toolu_c.txt", 4096, 20*day),
		d.save("active", "toolu_d.txt", 4096, time.Hour),
	}
	d.c.Prune()
	if d.exists(filepath.Join(d.c.dir, "codex-quiet")) {
		t.Fatalf("session kept with its newest output %v old", Retention+time.Minute)
	}
	for _, path := range active {
		if !d.exists(path) {
			t.Fatalf("%s deleted from a session that saved an hour ago", filepath.Base(path))
		}
	}
}

// Over maxSavedBytes, whole sessions go, the one whose newest output is
// oldest first, until the rest fit. A session's newest output orders it, not
// its oldest or its size.
func TestPruneCapDeletesTheSessionsSavedInLeastRecentlyFirst(t *testing.T) {
	d := newSavedDir(t)
	oldest := d.save("oldest", "toolu_1.txt", 100*mib, 3*day)
	older := d.save("older", "toolu_2.txt", 100*mib, 2*day)
	kept := []string{
		d.save("recent", "toolu_3.txt", 200*mib, day),
		d.save("long", "toolu_4.txt", 250*mib, 20*day),
		d.save("long", "toolu_5.txt", 4096, time.Hour),
	}
	// 650 MiB: the two oldest sessions go, which leaves 450.
	d.c.Prune()
	for _, path := range []string{oldest, older} {
		if d.exists(filepath.Dir(path)) {
			t.Fatalf("session %s kept over the cap", filepath.Base(filepath.Dir(path)))
		}
	}
	for _, path := range kept {
		if !d.exists(path) {
			t.Fatalf("%s deleted though the rest fit the cap", filepath.Base(path))
		}
	}
}

// The session with the newest output never goes for size. When it alone is
// over the cap, every other session goes and it is kept whole, until another
// session saves an output after it. A directory with no file holds no saved
// output and changes neither.
func TestPruneCapNeverDeletesTheSessionWithTheNewestOutput(t *testing.T) {
	d := newSavedDir(t)
	other := d.save("other", "toolu_1.txt", mib, 2*day)
	big := []string{
		d.save("big", "toolu_2.txt", 550*mib, 3*day),
		d.save("big", "toolu_3.txt", 50*mib, time.Hour),
	}
	empty := filepath.Join(d.c.dir, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	d.c.Prune()
	if d.exists(filepath.Dir(other)) {
		t.Fatal("older session kept over the cap")
	}
	for _, path := range big {
		if !d.exists(path) {
			t.Fatalf("%s deleted from the session with the newest output", filepath.Base(path))
		}
	}
	if !d.exists(empty) {
		t.Fatal("empty directory deleted for size")
	}

	next := d.save("next", "toolu_4.txt", 4096, 0)
	d.c.Prune()
	if d.exists(filepath.Dir(big[0])) {
		t.Fatal("session over the cap kept after another saved an output")
	}
	if !d.exists(next) {
		t.Fatal("session with the newest output deleted")
	}
}

// Only a directory is a session, and only its regular files are saved
// outputs. Nothing is followed through a link, and what is no session stays.
func TestPruneHandlesEmptyDirectoriesAndOddEntries(t *testing.T) {
	hermetic.Symlinks(t)
	d := newSavedDir(t)
	// A directory with no file goes by its own time: a new one may be a
	// save under way.
	fresh := filepath.Join(d.c.dir, "fresh-empty")
	stale := filepath.Join(d.c.dir, "stale-empty")
	for _, dir := range []string{fresh, stale} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	d.age(stale, Retention+time.Minute)

	// In a session, a link or a directory is no saved output however new,
	// and goes with the session. A link's target stays.
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("not saved here"), 0o600); err != nil {
		t.Fatal(err)
	}
	quiet := filepath.Dir(d.save("quiet", "toolu_old.txt", 4096, 20*day))
	if err := os.Symlink(outside, filepath.Join(quiet, "toolu_link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(quiet, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(quiet, "nested", "toolu_inner.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// At the top, a file or a link is no session: each stays as it is, and
	// a link to a directory is not followed into it.
	stray := filepath.Join(d.c.dir, "stray.txt")
	if err := os.WriteFile(stray, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	d.age(stray, 20*day)
	elsewhere := t.TempDir()
	target := filepath.Join(elsewhere, "toolu_far.txt")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	d.age(target, 20*day)
	linked := filepath.Join(d.c.dir, "linked")
	dangling := filepath.Join(d.c.dir, "dangling")
	for link, to := range map[string]string{linked: elsewhere, dangling: filepath.Join(elsewhere, "missing")} {
		if err := os.Symlink(to, link); err != nil {
			t.Fatal(err)
		}
	}

	d.c.Prune()
	for path, want := range map[string]bool{
		fresh: true, stale: false,
		quiet: false, outside: true,
		stray: true, linked: true, target: true, dangling: true,
	} {
		if got := d.exists(path); got != want {
			t.Errorf("%s exists = %v, want %v", filepath.Base(path), got, want)
		}
	}
}

// Prune waits for a save under way and scans what it leaves, so a session
// that saves while Prune runs keeps every output, its oldest and the new one.
// The save here is writePrivate's: a temporary file renamed into place, which
// keeps the time it was written.
func TestPruneWaitsForASaveUnderWay(t *testing.T) {
	d := newSavedDir(t)
	old := d.save("resumed", "toolu_old.txt", 4096, 20*day)
	saving.RLock()
	temporary := filepath.Join(filepath.Dir(old), ".tool-output-1.tmp")
	if err := os.WriteFile(temporary, []byte("output"), 0o600); err != nil {
		saving.RUnlock()
		t.Fatal(err)
	}
	pruned := make(chan struct{})
	go func() {
		defer close(pruned)
		d.c.Prune()
	}()
	select {
	case <-pruned:
		saving.RUnlock()
		t.Fatal("Prune ran while a save was under way")
	case <-time.After(100 * time.Millisecond):
	}
	fresh := filepath.Join(filepath.Dir(old), "toolu_new.txt")
	err := os.Rename(temporary, fresh)
	saving.RUnlock()
	if err != nil {
		t.Fatal(err)
	}
	<-pruned
	for _, path := range []string{old, fresh} {
		if !d.exists(path) {
			t.Fatalf("%s deleted from a session that saved while Prune ran", filepath.Base(path))
		}
	}
}

// A save waits while Prune scans and deletes.
func TestASaveWaitsForPrune(t *testing.T) {
	d := newSavedDir(t)
	saving.Lock()
	saved := make(chan error, 1)
	go func() {
		saved <- writePrivate(d.c.dir, filepath.Join(d.c.dir, "session", "toolu_1.txt"), []byte("output"))
	}()
	select {
	case err := <-saved:
		saving.Unlock()
		t.Fatalf("save ran while Prune held the directory: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	saving.Unlock()
	if err := <-saved; err != nil {
		t.Fatal(err)
	}
}
