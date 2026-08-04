package buildinfo

import (
	"runtime/debug"
	"testing"
)

// stubBuildInfo replaces the debug.ReadBuildInfo seam for one test. The real
// function cannot report a VCS stamp under `go test` — the test binary has none
// — so every assertion about stamp handling has to go through the seam.
func stubBuildInfo(t *testing.T, settings map[string]string, ok bool) {
	t.Helper()
	previous := read
	t.Cleanup(func() { read = previous })
	read = func() (*debug.BuildInfo, bool) {
		if !ok {
			return nil, false
		}
		info := &debug.BuildInfo{}
		for key, value := range settings {
			info.Settings = append(info.Settings, debug.BuildSetting{Key: key, Value: value})
		}
		return info, true
	}
}

func TestRevisionReadsVCSStamp(t *testing.T) {
	stubBuildInfo(t, map[string]string{"vcs.revision": "cac15fd669a7e4b0bfbdd78413d25fc0999e3a11"}, true)
	if got, want := Revision(), "cac15fd669a7e4b0bfbdd78413d25fc0999e3a11"; got != want {
		t.Fatalf("Revision() = %q, want %q", got, want)
	}
	if got, want := ShortRevision(), "cac15fd6"; got != want {
		t.Fatalf("ShortRevision() = %q, want %q", got, want)
	}
}

// A binary with no stamp must report nothing rather than something misleading:
// `go build` outside a repo and -buildvcs=false are both legitimate.
func TestRevisionEmptyWithoutStamp(t *testing.T) {
	stubBuildInfo(t, map[string]string{"GOARCH": "arm64"}, true)
	if got := Revision(); got != "" {
		t.Fatalf("Revision() = %q, want empty", got)
	}
	if got := ShortRevision(); got != "" {
		t.Fatalf("ShortRevision() = %q, want empty", got)
	}
}

func TestRevisionEmptyWhenBuildInfoUnavailable(t *testing.T) {
	stubBuildInfo(t, nil, false)
	if got := Revision(); got != "" {
		t.Fatalf("Revision() = %q, want empty", got)
	}
}

func TestModifiedReportsDirtyTree(t *testing.T) {
	stubBuildInfo(t, map[string]string{"vcs.modified": "true"}, true)
	if !Modified() {
		t.Fatal("Modified() = false, want true")
	}
	stubBuildInfo(t, map[string]string{"vcs.modified": "false"}, true)
	if Modified() {
		t.Fatal("Modified() = true, want false")
	}
}

func TestDescribe(t *testing.T) {
	for name, test := range map[string]struct {
		settings map[string]string
		want     string
	}{
		"stamped": {
			settings: map[string]string{"vcs.revision": "cac15fd669a7e4b", "vcs.modified": "false"},
			want:     "0.14.1 (cac15fd6)",
		},
		// A modified tree must say so: the revision names the commit the build
		// was based on, not what was compiled, so it is not an identity.
		"stamped and modified": {
			settings: map[string]string{"vcs.revision": "cac15fd669a7e4b", "vcs.modified": "true"},
			want:     "0.14.1 (cac15fd6+modified)",
		},
		"unstamped falls back to the bare version": {
			settings: map[string]string{},
			want:     "0.14.1",
		},
	} {
		t.Run(name, func(t *testing.T) {
			stubBuildInfo(t, test.settings, true)
			if got := Describe("0.14.1"); got != test.want {
				t.Fatalf("Describe() = %q, want %q", got, test.want)
			}
		})
	}
}

// One token, so callers can embed it mid-line without the marker reading as a
// separate field.
func TestDescribeRevision(t *testing.T) {
	for _, test := range []struct {
		revision string
		modified bool
		want     string
	}{
		{revision: "cac15fd669a7e4b", modified: false, want: "cac15fd6"},
		{revision: "cac15fd669a7e4b", modified: true, want: "cac15fd6+modified"},
		// Nothing to describe stays nothing to describe, dirty tree or not: a
		// build with no stamp must not start reporting a phantom identity.
		{revision: "", modified: true, want: ""},
		{revision: "", modified: false, want: ""},
	} {
		if got := DescribeRevision(test.revision, test.modified); got != test.want {
			t.Fatalf("DescribeRevision(%q, %v) = %q, want %q", test.revision, test.modified, got, test.want)
		}
	}
}

func TestShortHandlesArbitraryRevisions(t *testing.T) {
	for input, want := range map[string]string{
		"cac15fd669a7e4b0bfbdd78413d25fc0999e3a11": "cac15fd6",
		"  cac15fd669a7e4b  ":                      "cac15fd6",
		"short":                                    "short",
		"":                                         "",
	} {
		if got := Short(input); got != want {
			t.Fatalf("Short(%q) = %q, want %q", input, got, want)
		}
	}
}
