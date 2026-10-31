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

// maxShellDepth bounds how deep commands handed to another shell, as in
// bash -c '...', are read.
const maxShellDepth = 3

// touchesPrivacyFolder reports whether a call runs in, or names a path in, a
// folder macOS guards with a privacy prompt (internal/privacyfolder), or a
// folder holding one, which a recursive read reaches. Nothing from there is
// sent. Paths are found as pathScan finds them; one only known at run time
// cannot be checked, so it counts as touching one.
func touchesPrivacyFolder(home, cwd string, input any, paths ...string) bool {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	for _, path := range append([]string{cwd}, paths...) {
		if path != "" && privacyfolder.Guarded(home, path) {
			return true
		}
	}
	guarded := false
	scan := pathScan{home: home, visit: func(path string) bool {
		if strings.ContainsAny(path, "*?[") {
			guarded = privacyfolder.GuardedPattern(home, path)
		} else {
			guarded = privacyfolder.Guarded(home, path) || privacyfolder.Encloses(home, path)
		}
		return !guarded
	}}
	eachString(input, func(value string) bool {
		scan.value(value, cwd, 0, true)
		return !scan.stopped && !scan.unknown
	})
	return guarded || scan.unknown
}

// pathScan finds the paths a call's input names: each string whole when it
// is a path (a Read's file_path may hold spaces), and word by word as a shell
// would split it. ~, $HOME and $PWD are expanded, a relative path is taken
// from cwd and from every directory a cd moves to, and every path is cleaned.
// A command handed to another shell, as with bash -c or eval, is read as a
// command in turn; any other word of several words, an awk program or
// python -c code, say, is read only for the paths it spells out. In a
// command, a command substitution, any other expansion in a path word or
// another user's home names a path only known at run time, which it marks
// as unknown.
type pathScan struct {
	home string
	// visit gets each absolute, cleaned path; returning false stops the scan.
	visit   func(path string) bool
	checked int
	stopped bool
	unknown bool
}

// value scans one input string; command says whether a shell runs it.
func (s *pathScan) value(value, cwd string, depth int, command bool) {
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~/") {
		s.path(resolvePath(s.home, cwd, value))
	}
	words, substitutes := shellWords(value)
	s.unknown = s.unknown || command && substitutes
	dirs := []string{cwd}
	for i, word := range words {
		if s.stopped {
			return
		}
		if word.unverifiable() {
			s.unknown = s.unknown || command
			continue
		}
		if depth < maxShellDepth && strings.ContainsAny(word.text, " \t\r\n;|&<>()`") {
			s.value(word.text, dirs[len(dirs)-1], depth+1, command && shellArgument(words, i))
		}
		for _, candidate := range pathCandidates(word.text) {
			for _, dir := range dirs {
				s.path(resolvePath(s.home, dir, candidate))
			}
		}
		if word.text != "cd" && word.text != "pushd" {
			continue
		}
		// Later relative paths may be taken from where this moves to.
		target := s.home
		if i+1 < len(words) {
			if words[i+1].text == "-" {
				s.unknown = true
				continue
			}
			target = resolvePath(s.home, dirs[len(dirs)-1], words[i+1].text)
		}
		if target != "" {
			dirs = append(dirs, target)
		}
	}
}

// shellArgument reports whether words[i] is a command handed to another
// shell: eval's argument, or the one after a -c flag given to a shell.
func shellArgument(words []shellWord, i int) bool {
	if i == 0 {
		return false
	}
	if words[i-1].text == "eval" {
		return true
	}
	flag := words[i-1].text
	if flag != "--command" && (!strings.HasPrefix(flag, "-") || strings.HasPrefix(flag, "--") || !strings.Contains(flag, "c")) {
		return false
	}
	for _, word := range words[:i-1] {
		switch filepath.Base(word.text) {
		case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh":
			return true
		}
	}
	return false
}

func (s *pathScan) path(path string) {
	if path == "" || s.stopped {
		return
	}
	if s.checked++; s.checked > maxPathWords {
		s.unknown, s.stopped = true, true
		return
	}
	s.stopped = !s.visit(filepath.Clean(path))
}

// shellWord is a word as a shell would split it, with where it expands.
type shellWord struct {
	text string
	// expansions are the offsets in text of each $ the shell expands.
	expansions []int
}

// unverifiable reports a word that may name a path only known at run time:
// one with an expansion other than a leading $HOME or $PWD (all of it, or
// in a path), or another user's home. Wildcards are checked against the
// guarded folders once the path is resolved.
func (w shellWord) unverifiable() bool {
	switch w.text {
	case "$HOME", "${HOME}", "$PWD", "${PWD}":
		return false
	}
	known := false
	for _, prefix := range []string{"$HOME/", "${HOME}/", "$PWD/", "${PWD}/"} {
		known = known || strings.HasPrefix(w.text, prefix)
	}
	for _, at := range w.expansions {
		if known && at == 0 {
			continue
		}
		if at == 0 || strings.Contains(w.text, "/") {
			return true
		}
	}
	return strings.HasPrefix(w.text, "~") && w.text != "~" && !strings.HasPrefix(w.text, "~/")
}

// shellWords splits text into words as a shell would, honouring quotes and
// backslash escapes, and also breaks at the operators that join commands. It
// reports whether text substitutes a command's output (`...` or $(...)).
func shellWords(text string) ([]shellWord, bool) {
	var words []shellWord
	var word strings.Builder
	var expansions []int
	inWord, escaped, dollar, substitutes := false, false, false, false
	var quote rune
	flush := func() {
		if inWord {
			words = append(words, shellWord{text: word.String(), expansions: expansions})
			word.Reset()
			expansions, inWord = nil, false
		}
	}
	for _, c := range text {
		expands := quote != '\'' && !escaped
		if expands && (c == '`' || c == '(' && dollar) {
			substitutes = true
		}
		dollar = expands && c == '$'
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
			if dollar {
				expansions = append(expansions, word.Len())
			}
			word.WriteRune(c)
			inWord = true
		}
	}
	flush()
	return words, substitutes
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
