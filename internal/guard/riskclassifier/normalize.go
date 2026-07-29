// Package riskclassifier scores bash commands with the observe-mode risk model
// from the authz-bench serving contract: the shipped char n-gram + LinearSVM
// classifier, ported natively over an embedded artifact. Verdicts are recorded
// for feedback collection only; nothing in this package influences hook
// decisions.
package riskclassifier

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// NormalizeCommand is the Go port of authz-bench serve/classify.py
// normalize_command. Every command is normalized before classification —
// identically to training — or the model silently degrades. Behavior is locked
// to the Python reference by the golden fixtures in testdata/golden.jsonl;
// regenerate them with scripts/riskclassifier/export_portable.py when the
// upstream normalizer changes.
func NormalizeCommand(text string) string {
	if text == "" {
		return text
	}
	text = urlPattern.ReplaceAllString(text, "http://example.com")
	text = replaceIPs(text)
	return replaceBase64Runs(text)
}

// Python's re \s (and str.isspace) covers more than RE2's ASCII \s: the 0x1c-0x1f
// separators, NEL, and the Unicode Z categories. The URL pattern must stop at
// exactly the same characters as the reference.
const pythonWhitespaceClass = `\t-\r\x1c-\x1f\x{85}\p{Z}`

var (
	urlPattern = regexp.MustCompile(`(?i)https?://[^` + pythonWhitespaceClass + "'\"`;|)]+")
	ipPattern  = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}`)
)

// replaceIPs applies Python's \b(?:\d{1,3}\.){3}\d{1,3}\b. RE2 word boundaries
// are ASCII-only, so the boundary check runs outside the pattern: candidates are
// scanned left to right and rejected ones re-tried from the next byte, matching
// the reference engine's advance behavior.
func replaceIPs(text string) string {
	var out strings.Builder
	pos := 0
	for pos < len(text) {
		loc := ipPattern.FindStringIndex(text[pos:])
		if loc == nil {
			break
		}
		start, end := pos+loc[0], pos+loc[1]
		if hasPythonWordBoundary(text, start) && hasPythonWordBoundary(text, end) {
			out.WriteString(text[pos:start])
			out.WriteString("1.1.1.1")
			pos = end
			continue
		}
		out.WriteString(text[pos : start+1])
		pos = start + 1
	}
	out.WriteString(text[pos:])
	return out.String()
}

// hasPythonWordBoundary reports whether a \b holds at byte offset i, using
// Python's Unicode word definition (letters, numerics, underscore). Both
// matched edges here are ASCII digits, so only the outside rune needs
// classifying.
func hasPythonWordBoundary(text string, i int) bool {
	before := false
	if i > 0 {
		r, _ := utf8.DecodeLastRuneInString(text[:i])
		before = isPythonWordChar(r)
	}
	after := false
	if i < len(text) {
		r, _ := utf8.DecodeRuneInString(text[i:])
		after = isPythonWordChar(r)
	}
	return before != after
}

func isPythonWordChar(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsNumber(r)
}

// replaceBase64Runs applies Python's
// (?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/]) — RE2 has no
// lookarounds, so the run scan is hand-rolled. A maximal alphabet run at a
// non-alphabet left boundary is the only viable candidate (any shorter slice
// fails a lookaround), so the scan is: take the maximal run, require length
// >= 40, then consume up to two '=' as long as the character after them is not
// back in the alphabet.
func replaceBase64Runs(text string) string {
	isAlpha := func(b byte) bool {
		return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '+' || b == '/'
	}
	var out strings.Builder
	pos := 0
	for i := 0; i < len(text); {
		if !isAlpha(text[i]) {
			i++
			continue
		}
		if i > 0 && isAlpha(text[i-1]) {
			i++
			continue
		}
		end := i
		for end < len(text) && isAlpha(text[end]) {
			end++
		}
		if end-i < 40 {
			i = end
			continue
		}
		pad := 0
		for pad < 2 && end+pad < len(text) && text[end+pad] == '=' {
			pad++
		}
		for pad > 0 && end+pad < len(text) && isAlpha(text[end+pad]) {
			pad--
		}
		out.WriteString(text[pos:i])
		out.WriteString("BASE64")
		pos = end + pad
		i = pos
	}
	out.WriteString(text[pos:])
	return out.String()
}
