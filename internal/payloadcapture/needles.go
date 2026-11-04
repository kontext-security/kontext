package payloadcapture

import (
	"regexp/syntax"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// A value rule's needles are strings of which every match of its pattern
// contains one. Redaction looks for them before it runs the pattern: a search
// for fixed strings is far faster than running an expression over the same
// text, and most texts hold none of most rules' needles. Needles come from
// the pattern itself, so they hold for any ruleset, and they are compared
// folded (see fold), so they hold for case-insensitive patterns as well.

const (
	// maxNeedles bounds a set of needles, which grows as the fixed parts of
	// a pattern are combined.
	maxNeedles = 64
	// maxClassRunes is the largest character class taken as a set of fixed
	// strings.
	maxClassRunes = 16
)

// facts is what is known of the strings an expression matches, folded: all
// of them (exact), when they are few, strings of which each one starts with
// one (prefix), and strings of which each one contains one (need).
type facts struct {
	exact    []string
	exactOK  bool
	prefix   []string
	prefixOK bool
	need     []string
	needOK   bool
}

// needles returns a pattern's needles, or false when it has none and every
// text must be searched.
func needles(pattern string) ([]string, bool) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, false
	}
	return analyze(re).needles()
}

func analyze(re *syntax.Regexp) facts {
	switch re.Op {
	case syntax.OpNoMatch:
		return facts{exact: []string{}, exactOK: true, need: []string{}, needOK: true}
	case syntax.OpEmptyMatch, syntax.OpBeginLine, syntax.OpEndLine, syntax.OpBeginText, syntax.OpEndText,
		syntax.OpWordBoundary, syntax.OpNoWordBoundary:
		return facts{exact: []string{""}, exactOK: true}
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if !foldable(r, re.Flags&syntax.FoldCase != 0) {
				return facts{}
			}
		}
		return facts{exact: []string{fold(string(re.Rune))}, exactOK: true}
	case syntax.OpCharClass:
		var set []string
		for i := 0; i+1 < len(re.Rune); i += 2 {
			for r := re.Rune[i]; r <= re.Rune[i+1]; r++ {
				if len(set) == maxClassRunes || !foldable(r, false) {
					return facts{}
				}
				set = append(set, fold(string(r)))
			}
		}
		return facts{exact: dedupe(set), exactOK: true}
	case syntax.OpCapture:
		return analyze(re.Sub[0])
	case syntax.OpPlus:
		return repeated(analyze(re.Sub[0]))
	case syntax.OpQuest:
		return optional(analyze(re.Sub[0]))
	case syntax.OpRepeat:
		sub := analyze(re.Sub[0])
		if re.Min == 0 {
			if re.Max == 1 {
				return optional(sub)
			}
			return facts{}
		}
		return repeated(sub)
	case syntax.OpConcat:
		return concat(re.Sub)
	case syntax.OpAlternate:
		var exact, prefix, need []string
		exactOK, prefixOK, needOK := true, true, true
		for _, sub := range re.Sub {
			f := analyze(sub)
			exactOK = exactOK && f.exactOK
			exact = append(exact, f.exact...)
			p, ok := f.starts()
			prefixOK = prefixOK && ok
			prefix = append(prefix, p...)
			n, ok := f.needles()
			needOK = needOK && ok
			need = append(need, n...)
		}
		exact, prefix, need = dedupe(exact), dedupe(prefix), reduce(need)
		return facts{
			exact: exact, exactOK: exactOK && len(exact) <= maxNeedles,
			prefix: prefix, prefixOK: prefixOK && len(prefix) <= maxNeedles,
			need: need, needOK: needOK && len(need) <= maxNeedles,
		}
	}
	// Star and any character: anything at all may match.
	return facts{}
}

// optional is what is known of an expression that may also match nothing.
func optional(f facts) facts {
	if !f.exactOK {
		return facts{}
	}
	exact := dedupe(append(slices.Clone(f.exact), ""))
	return facts{exact: exact, exactOK: len(exact) <= maxNeedles}
}

// repeated is what is known of an expression repeated at least once.
func repeated(f facts) facts {
	prefix, prefixOK := f.starts()
	need, needOK := f.needles()
	return facts{prefix: prefix, prefixOK: prefixOK, need: need, needOK: needOK}
}

// concat is what is known of a sequence: each part's needles hold for it, and
// so do the strings consecutive fixed parts join into, followed by what the
// next part starts with.
func concat(subs []*syntax.Regexp) facts {
	var options [][]string
	run, exact, exactOK := []string{""}, []string{""}, true
	var prefix []string
	prefixOK, leading := false, true
	for _, sub := range subs {
		f := analyze(sub)
		if need, ok := f.needles(); ok {
			options = append(options, need)
		}
		if !f.exactOK {
			joined := run
			if starts, ok := f.starts(); ok {
				if next, ok := product(run, starts); ok {
					joined = next
				}
			}
			options = appendRun(options, joined)
			if leading {
				prefix, prefixOK, leading = joined, true, false
			}
			run, exactOK = []string{""}, false
			continue
		}
		if next, ok := product(run, f.exact); ok {
			run = next
		} else {
			options = appendRun(options, run)
			if leading {
				prefix, prefixOK, leading = run, true, false
			}
			run = f.exact
		}
		if exactOK {
			exact, exactOK = product(exact, f.exact)
		}
	}
	options = appendRun(options, run)
	need, ok := best(options)
	return facts{exact: exact, exactOK: exactOK, prefix: prefix, prefixOK: prefixOK, need: need, needOK: ok}
}

// starts returns strings of which every match starts with one.
func (f facts) starts() ([]string, bool) {
	if f.exactOK {
		return f.exact, true
	}
	return f.prefix, f.prefixOK
}

// appendRun adds the strings a run of fixed parts joins into as an option,
// unless the run may match nothing at all, which every text contains.
func appendRun(options [][]string, run []string) [][]string {
	if slices.Contains(run, "") {
		return options
	}
	return append(options, run)
}

func (f facts) needles() ([]string, bool) {
	var options [][]string
	if f.needOK {
		options = append(options, f.need)
	}
	if f.exactOK && !slices.Contains(f.exact, "") {
		options = append(options, f.exact)
	}
	return best(options)
}

// best is the option that rules out the most text: the one whose shortest
// needle is longest, then the one with fewest needles.
func best(options [][]string) ([]string, bool) {
	var chosen []string
	found := false
	shortest := func(set []string) int {
		n := -1
		for _, s := range set {
			if n < 0 || len(s) < n {
				n = len(s)
			}
		}
		if n < 0 {
			// No needle at all: nothing matches.
			return int(^uint(0) >> 1)
		}
		return n
	}
	for _, option := range options {
		option = reduce(option)
		if len(option) > maxNeedles {
			continue
		}
		if !found || shortest(option) > shortest(chosen) || shortest(option) == shortest(chosen) && len(option) < len(chosen) {
			chosen, found = option, true
		}
	}
	return chosen, found
}

func product(a, b []string) ([]string, bool) {
	if len(a)*len(b) > maxNeedles {
		return nil, false
	}
	out := make([]string, 0, len(a)*len(b))
	for _, x := range a {
		for _, y := range b {
			out = append(out, x+y)
		}
	}
	return dedupe(out), true
}

func dedupe(set []string) []string {
	set = slices.Clone(set)
	slices.Sort(set)
	return slices.Compact(set)
}

// reduce drops each needle that contains another: a text holding it holds
// the other too.
func reduce(set []string) []string {
	set = dedupe(set)
	slices.SortStableFunc(set, func(a, b string) int { return len(a) - len(b) })
	var out []string
	for _, s := range set {
		if !slices.ContainsFunc(out, func(kept string) bool { return strings.Contains(s, kept) }) {
			out = append(out, s)
		}
	}
	return out
}

// foldable reports whether a rune of a pattern can be part of a needle. The
// engine matches U+FFFD to any invalid byte, which a search for its encoding
// would miss; and a case-insensitive rune must have no variants besides those
// fold maps to it.
func foldable(r rune, foldCase bool) bool {
	if r == utf8.RuneError {
		return false
	}
	return !foldCase || r < utf8.RuneSelf || r == '\u017f' || r == '\u212a' || unicode.SimpleFold(r) == r
}

// fold maps text to the form needles are compared in: ASCII letters in lower
// case, and the only other letters Unicode folds to ASCII ones, the long s
// (U+017F) and the Kelvin sign (U+212A), as "s" and "k". A case-insensitive
// match of a needle is then a plain match of the folded needle in the folded
// text.
func fold(text string) string {
	var out []byte
	for i := 0; i < len(text); i++ {
		c, width := text[i], 1
		switch {
		case 'A' <= c && c <= 'Z':
			c += 'a' - 'A'
		case c == 0xc5 && strings.HasPrefix(text[i:], "\u017f"):
			c, width = 's', len("\u017f")
		case c == 0xe2 && strings.HasPrefix(text[i:], "\u212a"):
			c, width = 'k', len("\u212a")
		default:
			if out != nil {
				out = append(out, c)
			}
			continue
		}
		if out == nil {
			out = make([]byte, i, len(text))
			copy(out, text)
		}
		out = append(out, c)
		i += width - 1
	}
	if out == nil {
		return text
	}
	return string(out)
}

func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}
