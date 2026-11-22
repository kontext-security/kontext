package payloadcapture

import (
	"slices"
	"sort"
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
	return redactedSpans(value, compiledValueRules)
}

func redactedSpans(value string, rules []compiledRule) []Span {
	_, stretches, _ := redactWith(value, true, rules)
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

// maxPasses bounds the repeated pass, as in the cloud API: a few passes
// settle every input seen so far, and if one ever does not, the last pass
// wins, which only masks more.
const maxPasses = 4

// redact masks what the ruleset's value patterns find in value and repeats
// the pass until the text stops changing, so a placeholder one pass writes
// can complete a match (AKIA…pwd=SECRET). It reports whether anything
// changed. With track it also returns where each stretch of the result came
// from.
func redact(value string, track bool) (string, []stretch, bool) {
	return redactWith(value, track, compiledValueRules)
}

func redactWith(value string, track bool, rules []compiledRule) (string, []stretch, bool) {
	text, changed := value, false
	var stretches []stretch
	if track {
		stretches = appendStretch(nil, stretch{0, len(value)})
	}
	for pass := 0; pass < maxPasses; pass++ {
		before := text
		text, stretches = redactPass(text, stretches, track, rules)
		if text == before {
			break
		}
		changed = true
	}
	return text, stretches, changed
}

// redactPass runs every value pattern over the same text and masks the
// union of what they find, each merged run as one placeholder. No rule sees
// another's placeholders within a pass, so a rule can only add masks: none
// can take the text another needs to match.
func redactPass(text string, stretches []stretch, track bool, rules []compiledRule) (string, []stretch) {
	masks := passMasks(text, rules)
	if len(masks) == 0 {
		return text, stretches
	}
	return maskRuns(text, stretches, track, masks)
}

// passMasks is the merged union of every value pattern's masks on text,
// without the runs that are only placeholders already.
func passMasks(text string, rules []compiledRule) []Span {
	var spans []Span
	folded, foldedNow := "", false
	for index := range rules {
		rule := &rules[index]
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
		for _, match := range matches {
			spans = append(spans, rule.masked(text, match))
		}
	}
	return settledRuns(text, mergeSpans(spans))
}

// masked is the part of a match the rule replaces: the match without what
// its replacement keeps of its start and end, or all of it when the match
// does not start and end with that.
func (rule *compiledRule) masked(text string, match []int) Span {
	whole := text[match[0]:match[1]]
	kept := rule.before
	if rule.groups {
		kept = string(rule.re.ExpandString(nil, rule.before, text, match))
	}
	if len(kept)+len(rule.after) <= len(whole) && strings.HasPrefix(whole, kept) && strings.HasSuffix(whole, rule.after) {
		return Span{match[0] + len(kept), match[1] - len(rule.after)}
	}
	return Span{match[0], match[1]}
}

// mergeSpans sorts spans and joins those that overlap or touch. An empty
// span (an empty secret, {"token":""}) stays, and still gets a placeholder.
func mergeSpans(spans []Span) []Span {
	slices.SortFunc(spans, func(a, b Span) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		return a.End - b.End
	})
	var merged []Span
	for _, span := range spans {
		if n := len(merged); n > 0 && span.Start <= merged[n-1].End {
			merged[n-1].End = max(merged[n-1].End, span.End)
			continue
		}
		merged = append(merged, span)
	}
	return merged
}

// settledRuns drops the runs that are only placeholders, quotes and
// whitespace, which a pass would write back as they are: redacting
// redacted text changes nothing.
func settledRuns(text string, runs []Span) []Span {
	out := runs[:0]
	for _, run := range runs {
		masked := text[run.Start:run.End]
		if strings.Contains(masked, RedactedPlaceholder) &&
			strings.Trim(strings.ReplaceAll(masked, RedactedPlaceholder, ""), "'\"` \t\n\r\f") == "" {
			continue
		}
		out = append(out, run)
	}
	return out
}

// maskRuns writes a placeholder in place of each run (sorted and apart).
func maskRuns(text string, stretches []stretch, track bool, runs []Span) (string, []stretch) {
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
	for _, run := range runs {
		keep(last, run.Start)
		next.WriteString(RedactedPlaceholder)
		if track {
			nextStretches = appendStretch(nextStretches, stretch{-1, len(RedactedPlaceholder)})
		}
		last = run.End
	}
	keep(last, len(text))
	return next.String(), nextStretches
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
