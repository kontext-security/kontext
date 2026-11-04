//go:build darwin || linux

package codexroute

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// openLog opens path as launchd opens the job's log for its standard output
// and error.
func openLog(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}

func mustWrite(t *testing.T, w io.Writer, text string) {
	t.Helper()
	if _, err := io.WriteString(w, text); err != nil {
		t.Fatal(err)
	}
}

// logLine is a 40-byte log line of c.
func logLine(c string) string { return strings.Repeat(c, 39) + "\n" }

// The job's log starts again before a line would take it past its limit: the
// last one stays beside it, the only one kept, and standard output and error
// both write to the new one, as a crash's trace does.
func TestTheJobsLogStartsAgainPastItsLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "codex-proxy.log")
	stdout, stderr := openLog(t, path), openLog(t, path)
	log := jobLogFor(path, 100, io.Discard, stdout, stderr)
	mustWrite(t, log, logLine("a"))
	mustWrite(t, log, logLine("b"))
	mustWrite(t, log, logLine("c"))
	if got := readFile(t, path); got != logLine("c") {
		t.Fatalf("log after the limit:\n%s", got)
	}
	if got := readFile(t, path+".1"); got != logLine("a")+logLine("b") {
		t.Fatalf("the last log:\n%s", got)
	}
	mustWrite(t, stderr, "panic\n")
	mustWrite(t, stdout, "out\n")
	mustWrite(t, log, logLine("d"))
	if got := readFile(t, path); got != logLine("c")+"panic\nout\n"+logLine("d") {
		t.Fatalf("log:\n%s", got)
	}
	mustWrite(t, log, logLine("e"))
	if got := readFile(t, path+".1"); got != logLine("c")+"panic\nout\n"+logLine("d") {
		t.Fatalf("the last log after starting again twice:\n%s", got)
	}
	if got := readFile(t, path); got != logLine("e") {
		t.Fatalf("log after starting again twice:\n%s", got)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 2 {
		t.Fatalf("logs kept: %v, %v", entries, err)
	}
	// A line longer than the limit goes whole into a log of its own.
	long := strings.Repeat("f", 150) + "\n"
	mustWrite(t, log, long)
	mustWrite(t, log, logLine("g"))
	if readFile(t, path+".1") != long || readFile(t, path) != logLine("g") {
		t.Fatalf("a long line:\n%s\n---\n%s", readFile(t, path+".1"), readFile(t, path))
	}
}

// Only a job whose standard error is its log, as launchd opens it from the
// plist, starts the log again; a proxy run by hand logs where it would
// otherwise, and a standard output that goes elsewhere stays there.
func TestOnlyTheJobsOwnLogStartsAgain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "codex-proxy.log")
	terminal := openLog(t, filepath.Join(dir, "terminal"))
	var fallback bytes.Buffer
	if log := jobLogFor(path, 100, &fallback, terminal, terminal); log != io.Writer(&fallback) {
		t.Fatalf("a proxy without the job's log logs to %T", log)
	}
	writeFile(t, path, "", 0o644)
	if log := jobLogFor(path, 100, &fallback, terminal, terminal); log != io.Writer(&fallback) {
		t.Fatalf("a proxy whose standard error is elsewhere logs to %T", log)
	}

	stderr := openLog(t, path)
	log := jobLogFor(path, 100, &fallback, terminal, stderr)
	mustWrite(t, log, logLine("a"))
	mustWrite(t, log, logLine("b"))
	mustWrite(t, log, logLine("c"))
	mustWrite(t, terminal, "terminal\n")
	if readFile(t, filepath.Join(dir, "terminal")) != "terminal\n" || readFile(t, path) != logLine("c") || fallback.Len() != 0 {
		t.Fatalf("terminal %q, log %q, fallback %q", readFile(t, filepath.Join(dir, "terminal")), readFile(t, path), fallback.String())
	}
}

// A run that finds its log started again by another run, as two overlap
// across a reload, writes to the new one rather than start it again itself;
// so does one whose log was deleted, which it starts again.
func TestARunFollowsTheLogAnotherStartedAgain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codex-proxy.log")
	firstFile, secondFile := openLog(t, path), openLog(t, path)
	first := jobLogFor(path, 100, io.Discard, firstFile, firstFile)
	second := jobLogFor(path, 100, io.Discard, secondFile, secondFile)
	mustWrite(t, first, logLine("a"))
	mustWrite(t, second, logLine("b"))
	mustWrite(t, first, logLine("c"))
	mustWrite(t, second, logLine("d"))
	if readFile(t, path+".1") != logLine("a")+logLine("b") || readFile(t, path) != logLine("c")+logLine("d") {
		t.Fatalf("logs:\n%s\n---\n%s", readFile(t, path+".1"), readFile(t, path))
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, first, "e\n")
	mustWrite(t, second, "f\n")
	if readFile(t, path) != "e\nf\n" {
		t.Fatalf("log after it was deleted:\n%s", readFile(t, path))
	}
}
