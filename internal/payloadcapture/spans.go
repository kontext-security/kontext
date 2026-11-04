package payloadcapture

import (
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Span is the byte range [Start, End) of a text.
type Span struct {
	Start, End int
}

// RedactedSpans returns the byte ranges of value that RedactText removes, in
// order, apart and not empty. Every byte outside them is one RedactText
// keeps, so a caller that replaces the spans with placeholders of its own
// sends no more of value than RedactText would, and can put them back.
func RedactedSpans(value string) []Span {
	_, stretches, _ := redact(value, true)
	var kept []Span
	for _, s := range stretches {
		if s.from >= 0 {
			kept = append(kept, Span{s.from, s.from + s.len})
		}
	}
	slices.SortFunc(kept, func(a, b Span) int { return a.Start - b.Start })
	var removed []Span
	at := 0
	for _, k := range kept {
		if k.Start > at {
			removed = append(removed, Span{at, k.Start})
		}
		at = max(at, k.End)
	}
	if at < len(value) {
		removed = append(removed, Span{at, len(value)})
	}
	return removed
}

// stretch is a part of the text redaction works on: from is where it starts
// in the original text, or -1 for text a replacement wrote.
type stretch struct {
	from, len int
}

// redact runs the ruleset's value patterns over value in order, each over
// what the ones before it left, and reports whether anything changed. With
// track it also returns where each stretch of the result came from.
func redact(value string, track bool) (string, []stretch, bool) {
	text, changed := value, false
	var stretches []stretch
	if track {
		stretches = appendStretch(nil, stretch{0, len(value)})
	}
	folded, foldedNow := "", false
	for _, rule := range compiledValueRules {
		if rule.filtered {
			if !foldedNow {
				folded, foldedNow = fold(text), true
			}
			if !containsAny(folded, rule.needles) {
				continue
			}
		}
		var matches [][]int
		if rule.groups {
			matches = rule.re.FindAllStringSubmatchIndex(text, -1)
		} else {
			matches = rule.re.FindAllStringIndex(text, -1)
		}
		if len(matches) == 0 {
			continue
		}
		var next strings.Builder
		next.Grow(len(text))
		var nextStretches []stretch
		var starts []int
		if track {
			starts = make([]int, len(stretches))
			for i := 1; i < len(stretches); i++ {
				starts[i] = starts[i-1] + stretches[i-1].len
			}
		}
		keep := func(a, b int) {
			next.WriteString(text[a:b])
			if track {
				nextStretches = appendRange(nextStretches, stretches, starts, a, b)
			}
		}
		last := 0
		for _, match := range matches {
			keep(last, match[0])
			for _, p := range rule.pieces {
				if p.group < 0 {
					next.WriteString(p.text)
					if track {
						nextStretches = appendStretch(nextStretches, stretch{-1, len(p.text)})
					}
				} else if 2*p.group+1 < len(match) && match[2*p.group] >= 0 {
					keep(match[2*p.group], match[2*p.group+1])
				}
			}
			last = match[1]
		}
		keep(last, len(text))
		if result := next.String(); result != text {
			text, changed, foldedNow = result, true, false
		}
		stretches = nextStretches
	}
	return text, stretches, changed
}

// appendRange appends the stretches that make up text[a:b], where starts
// holds the offset in text of each of stretches.
func appendRange(out, stretches []stretch, starts []int, a, b int) []stretch {
	for i := sort.SearchInts(starts, a+1) - 1; a < b; i++ {
		s, start := stretches[i], starts[i]
		end := min(b, start+s.len)
		from := -1
		if s.from >= 0 {
			from = s.from + a - start
		}
		out = appendStretch(out, stretch{from, end - a})
		a = end
	}
	return out
}

// appendStretch appends s, joined to the last stretch when it continues it.
func appendStretch(out []stretch, s stretch) []stretch {
	if s.len == 0 {
		return out
	}
	if n := len(out); n > 0 {
		last := &out[n-1]
		if last.from < 0 && s.from < 0 || last.from >= 0 && s.from == last.from+last.len {
			last.len += s.len
			return out
		}
	}
	return append(out, s)
}

// piece is a part of a rule's replacement: text, or when group is not -1 the
// text the match's capture group of that number matched.
type piece struct {
	text  string
	group int
}

// pieces splits a replacement template the way Regexp.Expand reads it, by
// expanding it for a match whose every group matched a marker of its own.
// The template must not contain a NUL byte, which the markers are made of.
func pieces(re *regexp.Regexp, template string) []piece {
	var src strings.Builder
	var match []int
	for group := range re.NumSubexp() + 1 {
		match = append(match, src.Len())
		src.WriteString("\x00" + strconv.Itoa(group) + "\x00")
		match = append(match, src.Len())
	}
	expanded := string(re.ExpandString(nil, template, src.String(), match))
	var out []piece
	for expanded != "" {
		text, rest, found := strings.Cut(expanded, "\x00")
		if text != "" {
			out = append(out, piece{text: text, group: -1})
		}
		if !found {
			break
		}
		number, after, _ := strings.Cut(rest, "\x00")
		group, _ := strconv.Atoi(number)
		out = append(out, piece{group: group})
		expanded = after
	}
	return out
}
