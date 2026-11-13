package agenthooks

import (
	"strings"
	"unicode/utf8"
)

// Codex on Windows hands every hook command to PowerShell as one string; it
// has no form that starts a program directly. PowerShell cannot parse the
// POSIX quoting written elsewhere: a quoted word at the start of a line is a
// string, not a command. So the command is written for PowerShell.

// The command line is "$LASTEXITCODE = 1; & 'program' 'word' ...; exit
// $LASTEXITCODE". The call operator runs the program; the rest hands its exit
// code on. Without it PowerShell answers 1 for every exit code that is not 0,
// and an agent that reads a meaning into the code would read the wrong one.
// The 1 set first is what comes back when the program cannot be started at
// all: $LASTEXITCODE then keeps its value, and unset it would give 0, which
// reads as a hook that ran and had nothing to say. (Measured with PowerShell
// 7 and Windows PowerShell 5.1.)
const (
	powerShellStart = "$LASTEXITCODE = 1; &"
	powerShellExit  = "; exit $LASTEXITCODE"
)

// PowerShellCommand is a command line PowerShell runs as words[0] with the
// other words as its arguments, every word taken literally.
func PowerShellCommand(words ...string) string {
	quoted := make([]string, len(words))
	for i, word := range words {
		quoted[i] = powerShellQuote(word)
	}
	return powerShellStart + " " + strings.Join(quoted, " ") + powerShellExit
}

// powerShellQuoteMark reports a character that ends a single-quoted string in
// PowerShell. The typographic quotes do, as the plain one does (measured with
// both PowerShells); a folder can carry one in its name.
func powerShellQuoteMark(r rune) bool {
	switch r {
	case '\'', '\u2018', '\u2019', '\u201A', '\u201B':
		return true
	}
	return false
}

// powerShellQuote is a single-quoted PowerShell string: nothing in it is
// expanded, and a quote mark in it is written twice. Every other byte of the
// word is kept as it is, also one that is not valid UTF-8.
func powerShellQuote(word string) string {
	return "'" + doubleQuoteMarks.Replace(word) + "'"
}

var doubleQuoteMarks = strings.NewReplacer(
	"'", "''",
	"\u2018", "\u2018\u2018",
	"\u2019", "\u2019\u2019",
	"\u201A", "\u201A\u201A",
	"\u201B", "\u201B\u201B",
)

// SplitPowerShellCommand reads a command PowerShellCommand wrote back into
// its words. It reports false for anything else, so a command edited by hand
// into something that expands, pipes or runs more is not taken for it.
func SplitPowerShellCommand(command string) ([]string, bool) {
	rest, ok := strings.CutSuffix(command, powerShellExit)
	if !ok {
		return nil, false
	}
	rest, ok = strings.CutPrefix(rest, powerShellStart)
	if !ok {
		return nil, false
	}
	var words []string
	for rest != "" {
		// One space, then a quoted word.
		if !strings.HasPrefix(rest, " '") {
			return nil, false
		}
		word, after, ok := powerShellWord(rest[2:])
		if !ok {
			return nil, false
		}
		words, rest = append(words, word), after
	}
	return words, len(words) > 0
}

// powerShellWord reads one word up to its closing quote and returns what
// follows. A quote mark written twice is that mark; a plain one alone closes
// the word; a typographic one alone would close it too in PowerShell, which
// PowerShellCommand never writes, so the command is refused.
func powerShellWord(rest string) (word, after string, ok bool) {
	var read strings.Builder
	for rest != "" {
		r, size := utf8.DecodeRuneInString(rest)
		mark, tail := rest[:size], rest[size:]
		if !powerShellQuoteMark(r) {
			read.WriteString(mark)
			rest = tail
			continue
		}
		if strings.HasPrefix(tail, mark) {
			read.WriteString(mark)
			rest = tail[size:]
			continue
		}
		if r != '\'' {
			return "", "", false
		}
		return read.String(), tail, true
	}
	return "", "", false
}
