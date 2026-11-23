//go:build !windows

package browserevents

import (
	"os"
	"testing"
)

// A store file others can read, such as one restored from a backup, is
// written again private when it is opened.
func TestAStoreOthersCanReadIsMadePrivate(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	if err := os.Chmod(s.path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openStore(s.path, testNow); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("mode = %#o", info.Mode().Perm())
	}
}

// Rows in a store file others could change are not read: they could have
// been put there to leave with this enrollment's token.
func TestRowsOfAStoreOthersCouldChangeAreNotRead(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	if err := os.Chmod(s.path, 0o664); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(s.path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(reopened.Pending(10).Records); n != 0 {
		t.Fatalf("%d rows read from a file others could change", n)
	}
}

// A backup restored read-only for its owner keeps its rows: no other
// account could have changed it.
func TestRowsOfAnOwnerReadOnlyStoreAreRead(t *testing.T) {
	s := openTestStore(t)
	_, _ = s.Apply(testExtension, s.Enrollment(), []IndexedRecord{visit(2, "2026-11-20T08:00:00Z", "2026-11-20T08:00:00Z")})
	if err := os.Chmod(s.path, 0o400); err != nil {
		t.Fatal(err)
	}
	reopened, err := openStore(s.path, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Bind(Binding("https://app.kontext.dev", "ins_0123456789abcdefghijklmnopqrstuv", "workspace-a")); err != nil {
		t.Fatal(err)
	}
	if n := len(reopened.Pending(10).Records); n != 1 {
		t.Fatalf("%d rows read, want 1", n)
	}
}
