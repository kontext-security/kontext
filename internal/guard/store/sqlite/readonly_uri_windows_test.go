package sqlite

import "testing"

func TestReadOnlyURIOnWindows(t *testing.T) {
	for path, want := range map[string]string{
		`C:\Users\a b\guard.db`:   "file:///C:/Users/a%20b/guard.db?mode=ro",
		`C:\Users\a#b\guard.db`:   "file:///C:/Users/a%23b/guard.db?mode=ro",
		`\\server\share\guard.db`: "file:////server/share/guard.db?mode=ro",
		`sub\guard.db`:            "file:sub/guard.db?mode=ro",
	} {
		if got := readOnlyURI(path); got != want {
			t.Errorf("readOnlyURI(%q) = %q; want %q", path, got, want)
		}
	}
}
