package tooloutput

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kontext-security/kontext/internal/fsperm"
)

// maxPathWords bounds how many paths are read from one call's input.
const maxPathWords = 1024

// DefaultDirForDB is where the daemon saves full outputs: next to its
// database, in the data directory only its user can read.
func DefaultDirForDB(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "tool-output")
}

var segmentPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// safeSegment reports whether value can name a directory or file under the
// save directory as is.
func safeSegment(value string) bool {
	return segmentPattern.MatchString(value) && value != "." && value != ".."
}

// eachString calls visit with every string in a decoded JSON value, until
// visit returns false. A Bash call's description is prose about the call, not
// part of it, and is skipped.
func eachString(value any, visit func(string) bool) bool {
	switch typed := value.(type) {
	case string:
		return visit(typed)
	case map[string]any:
		for key, item := range typed {
			if key != "description" && !eachString(item, visit) {
				return false
			}
		}
	case []any:
		for _, item := range typed {
			if !eachString(item, visit) {
				return false
			}
		}
	}
	return true
}

// maxShellDepth bounds how deep words holding commands, as handed to
// bash -c, are read.
const maxShellDepth = 3

// maxScanBytes bounds how much of a call's input one scan reads, nested
// commands included. A scan that would read more stops short.
const maxScanBytes = 1 << 20

// pathScan finds the paths a call's input names, as text only: it never
// touches the filesystem, so no folder macOS guards is ever opened. Each
// string is read whole when it is a path (a Read's file_path may hold
// spaces), and word by word as a shell would split it; a word of several
// words, such as a command handed to bash -c, is read in turn. ~, $HOME and
// $PWD are expanded, a relative path is taken from cwd and from every
// directory a cd moves to, and every path is cleaned.
type pathScan struct {
	home string
	// visit gets each absolute, cleaned path; returning false stops the scan.
	visit   func(path string) bool
	checked int
	read    int
	stopped bool
	// short is set when the scan stopped before reading the whole input,
	// past maxScanBytes or maxPathWords; what it did not read is unknown.
	short bool
}

func (s *pathScan) value(value, cwd string, depth int) {
	if s.stopped {
		return
	}
	if s.read += len(value); s.read > maxScanBytes {
		s.short, s.stopped = true, true
		return
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~/") {
		s.path(resolvePath(s.home, cwd, value))
	}
	dirs := []string{cwd}
	moving := false // the word before was cd or pushd
	eachWord(value, func(word string) bool {
		if moving {
			// Later relative paths may be taken from where it moves to.
			if target := resolvePath(s.home, dirs[len(dirs)-1], word); target != "" {
				dirs = append(dirs, target)
			}
			moving = false
		}
		if depth < maxShellDepth && strings.ContainsAny(word, " \t\r\n;|&<>()`") {
			s.value(word, dirs[len(dirs)-1], depth+1)
		}
		for _, candidate := range pathCandidates(word) {
			for _, dir := range dirs {
				s.path(resolvePath(s.home, dir, candidate))
			}
		}
		moving = word == "cd" || word == "pushd"
		return !s.stopped
	})
}

func (s *pathScan) path(path string) {
	if path == "" || s.stopped {
		return
	}
	if s.checked++; s.checked > maxPathWords {
		s.short, s.stopped = true, true
		return
	}
	s.stopped = !s.visit(filepath.Clean(path))
}

// eachWord calls visit with each word of text as a shell would split it,
// honouring quotes and backslash escapes and breaking at the operators that
// join commands, until visit returns false. It holds one word at a time.
func eachWord(text string, visit func(word string) bool) {
	var word strings.Builder
	inWord, escaped := false, false
	var quote rune
	flush := func() bool {
		if !inWord {
			return true
		}
		done := word.String()
		word.Reset()
		inWord = false
		return visit(done)
	}
	for _, c := range text {
		switch {
		case escaped:
			word.WriteRune(c)
			escaped, inWord = false, true
		case c == '\\' && quote != '\'':
			escaped, inWord = true, true
		case quote != 0 && c == quote:
			quote = 0
		case quote == 0 && (c == '\'' || c == '"'):
			quote, inWord = c, true
		case quote == 0 && strings.ContainsRune(" \t\r\n;|&<>()`", c):
			if !flush() {
				return
			}
		default:
			word.WriteRune(c)
			inWord = true
		}
	}
	flush()
}

// pathCandidates returns a word and the parts of it an option or a path list
// can carry a path in: after "=", and between ":".
func pathCandidates(word string) []string {
	candidates := []string{word}
	if _, value, found := strings.Cut(word, "="); found {
		candidates = append(candidates, value)
	}
	if strings.Contains(word, ":") {
		candidates = append(candidates, strings.Split(word, ":")...)
	}
	return candidates
}

// resolvePath turns a word into the absolute path it names, or "" for a word
// that names none: an option, or a bare word with no cwd to resolve it in.
func resolvePath(home, cwd, word string) string {
	for _, prefix := range []string{"~/", "$HOME/", "${HOME}/"} {
		if rest, found := strings.CutPrefix(word, prefix); found && home != "" {
			return filepath.Join(home, rest)
		}
	}
	for _, prefix := range []string{"$PWD/", "${PWD}/"} {
		if rest, found := strings.CutPrefix(word, prefix); found && cwd != "" {
			return filepath.Join(cwd, rest)
		}
	}
	switch {
	case word == "" || strings.HasPrefix(word, "-"):
		return ""
	case (word == "~" || word == "$HOME" || word == "${HOME}") && home != "":
		return home
	case (word == "$PWD" || word == "${PWD}") && cwd != "":
		return cwd
	case filepath.IsAbs(word):
		return filepath.Clean(word)
	case cwd != "" && filepath.IsAbs(cwd):
		return filepath.Join(cwd, word)
	}
	return ""
}

// inside reports path at or below root, ignoring case as APFS does.
func inside(path, root string) bool {
	path, root = strings.ToLower(filepath.Clean(path)), strings.ToLower(filepath.Clean(root))
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}

// savedRef is a saved output a call's input names.
type savedRef struct {
	session, name string
}

// normalizedPath undoes the spellings a path to the save directory can take
// in a command: a backslash-escaped space and Windows separators.
func normalizedPath(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, `\ `, " "), `\`, "/")
}

// saveDirName is the tail of dir that any spelling of a path into it
// contains, whether absolute, quoted, escaped or from ~: its last two
// components ("managed-observe/tool-output" by default).
func saveDirName(dir string) string {
	dir = filepath.ToSlash(filepath.Clean(dir))
	parent := filepath.ToSlash(filepath.Base(filepath.Dir(dir)))
	return parent + "/" + filepath.ToSlash(filepath.Base(dir))
}

func savedRefPattern(dirName string) *regexp.Regexp {
	return regexp.MustCompile(regexp.QuoteMeta(dirName) + `/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+)\.txt`)
}

// writePrivate writes data to path through a temporary file, readable by its
// owner only, in directories only the owner can enter.
func writePrivate(root, path string, data []byte) error {
	for _, dir := range []string{root, filepath.Dir(path)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".tool-output-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	err = fsperm.RestrictFile(temporary)
	if err == nil {
		_, err = temporary.Write(data)
	}
	err = errors.Join(err, temporary.Close())
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("save %s: %w", filepath.Base(path), err)
	}
	return nil
}
