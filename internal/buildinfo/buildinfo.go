// Package buildinfo exposes the source revision compiled into this binary.
//
// The version string alone cannot identify a build. It is injected at link time
// (`-X main.version=…`), so it carries whatever the release pipeline chose to
// call the build and nothing about what was compiled: two binaries can share a
// version string and differ in source, and one source tree can be published
// under several strings. Release channels that label builds by date rather than
// by source make this routine rather than theoretical.
//
// The Go toolchain already stamps the real answer into every binary built from
// a repository — `vcs.revision`, plus `vcs.modified` for an uncommitted tree —
// and it is not spoofable by a link-time flag. This package reads it so the CLI
// can report which source it is, and so two processes from the same install
// (the CLI and the long-lived daemon) can be compared for real.
package buildinfo

import (
	"runtime/debug"
	"strings"
)

// shortRevisionLength matches the abbreviation git uses in log output, which is
// what a reader will compare it against.
const shortRevisionLength = 8

// read is a test seam for debug.ReadBuildInfo, which cannot be made to report a
// VCS stamp from inside `go test` (the test binary has no stamp of its own).
var read = debug.ReadBuildInfo

// Revision is the full VCS revision this binary was built from, or "" when the
// binary carries no VCS stamp. Builds produced by `go build` outside a
// repository, or with -buildvcs=false, legitimately have none.
func Revision() string {
	return setting("vcs.revision")
}

// Modified reports whether the working tree had uncommitted changes at build
// time. A modified tree means Revision names the commit the build was based on,
// not the source that was actually compiled, so it must never be presented as
// an exact identity.
func Modified() bool {
	return setting("vcs.modified") == "true"
}

// ShortRevision abbreviates Revision for display, returning "" when there is no
// stamp to abbreviate.
func ShortRevision() string {
	return Short(Revision())
}

// Short abbreviates any revision for display, including one read back from
// another process's breadcrumb rather than from this binary.
func Short(revision string) string {
	revision = strings.TrimSpace(revision)
	if len(revision) > shortRevisionLength {
		return revision[:shortRevisionLength]
	}
	return revision
}

// DescribeRevision renders a revision for display as a single token, marking one
// that was built from a modified tree. Kept to one token because callers embed
// it inside longer lines ("daemon: running (v0.14.1 cac15fd6+modified, pid 12)")
// where a comma-separated qualifier would read as a separate field.
//
//	cac15fd6
//	cac15fd6+modified
//	""            (no stamp to describe)
func DescribeRevision(revision string, modified bool) string {
	revision = Short(revision)
	if revision == "" || !modified {
		return revision
	}
	return revision + "+modified"
}

// Describe renders version together with the source it was built from, for
// `kontext --version` and any other human-facing identity. The revision is
// additive: a binary with no stamp reports exactly what it did before.
//
//	0.14.1 (cac15fd6)
//	0.14.1 (cac15fd6+modified)
//	0.14.1
func Describe(version string) string {
	revision := DescribeRevision(Revision(), Modified())
	if revision == "" {
		return version
	}
	return version + " (" + revision + ")"
}

func setting(key string) string {
	info, ok := read()
	if !ok {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == key {
			return s.Value
		}
	}
	return ""
}
