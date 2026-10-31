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
	stopped bool
}

func (s *pathScan) value(value, cwd string, depth int) {
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~/") {
		s.path(resolvePath(s.home, cwd, value))
	}
	words := shellWords(value)
	dirs := []string{cwd}
	for i, word := range words {
		if s.stopped {
			return
		}
		if depth < maxShellDepth && strings.ContainsAny(word, " \t\r\n;|&<>()`") {
			s.value(word, dirs[len(dirs)-1], depth+1)
		}
		for _, candidate := range pathCandidates(word) {
			for _, dir := range dirs {
				s.path(resolvePath(s.home, dir, candidate))
			}
		}
		if word != "cd" && word != "pushd" {
			continue
		}
		// Later relative paths may be taken from where this moves to.
		target := s.home
		if i+1 < len(words) {
			target = resolvePath(s.home, dirs[len(dirs)-1], words[i+1])
		}
		if target != "" {
			dirs = append(dirs, target)
		}
	}
}

func (s *pathScan) path(path string) {
	if path == "" || s.stopped {
		return
	}
	if s.checked++; s.checked > maxPathWords {
		s.stopped = true
		return
	}
	s.stopped = !s.visit(filepath.Clean(path))
}

// shellWords splits text into words as a shell would, honouring quotes and
// backslash escapes, and also breaks at the operators that join commands.
func shellWords(text string) []string {
	var words []string
	var word strings.Builder
	inWord, escaped := false, false
	var quote rune
	flush := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
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
			flush()
		default:
			word.WriteRune(c)
			inWord = true
		}
	}
	flush()
	return words
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
