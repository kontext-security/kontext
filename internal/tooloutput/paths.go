package tooloutput

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kontext-security/kontext/internal/fsperm"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

// maxPathWords bounds how many words of a call's input are checked against
// the privacy folders. A call naming more is treated as touching one.
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

// touchesPrivacyFolder reports whether a call runs in, or names a path in, a
// folder macOS guards with a privacy prompt (internal/privacyfolder). Nothing
// from there is sent. Paths are read from the input's words as a shell would
// split them, with ~ and $HOME expanded and relative ones taken from cwd.
// This cannot see a path a command builds at run time.
func touchesPrivacyFolder(home, cwd string, input any, paths ...string) bool {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	for _, path := range append([]string{cwd}, paths...) {
		if path != "" && privacyfolder.Guarded(home, path) {
			return true
		}
	}
	checked, guarded := 0, false
	eachString(input, func(value string) bool {
		for _, word := range shellWords(value) {
			for _, candidate := range pathCandidates(word) {
				path := resolvePath(home, cwd, candidate)
				if path == "" {
					continue
				}
				if checked++; checked > maxPathWords || privacyfolder.Guarded(home, path) {
					guarded = true
					return false
				}
			}
		}
		return true
	})
	return guarded
}

// shellWords splits text into words as a shell would, honouring quotes and
// backslash escapes, and also breaks at the operators that join commands.
func shellWords(text string) []string {
	var words []string
	var word strings.Builder
	inWord := false
	var quote rune
	escaped := false
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
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				word.WriteRune(c)
			}
		case c == '\'' || c == '"':
			quote, inWord = c, true
		case strings.ContainsRune(" \t\r\n;|&<>()`", c):
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
	switch {
	case word == "" || strings.HasPrefix(word, "-"):
		return ""
	case (word == "~" || word == "$HOME" || word == "${HOME}") && home != "":
		return home
	case filepath.IsAbs(word):
		return filepath.Clean(word)
	case cwd != "" && filepath.IsAbs(cwd):
		return filepath.Join(cwd, word)
	}
	return ""
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
