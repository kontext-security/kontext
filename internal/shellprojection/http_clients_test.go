package shellprojection

import "testing"

// A command's program path is shell text, POSIX on every host, Windows
// included.
func TestStandardUtilityPathReadsPOSIXPaths(t *testing.T) {
	for _, tc := range []struct {
		program string
		want    bool
	}{
		{"cat", true},
		{"/bin/cat", true},
		{"/usr/bin/printf", true},
		{"/opt/homebrew/bin/jq", true},
		{"./cleanup.sh", false},
		{"/home/alice/bin/cat", false},
	} {
		if got := standardUtilityPath(tc.program); got != tc.want {
			t.Errorf("standardUtilityPath(%q) = %v, want %v", tc.program, got, tc.want)
		}
	}
}
