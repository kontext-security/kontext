package payloadcapture

import (
	"strings"
	"testing"
)

// ruleChain is RedactText without needles or stretches: each pass masks
// the union of what two readings of the rules mask (the command rules and
// every value rule over the same text, and the command rules then the value
// rules in order over what the ones before left), both
// run until they settle, and the passes repeat until the text stops
// changing. Each byte of a reading's text records the range of the pass's
// text it stands for.
func ruleChain(value string) string {
	for pass := 0; pass < maxPasses; pass++ {
		masks := append(chainReading(value, false), chainReading(value, true)...)
		next := keptText(value, settledRuns(value, mergeSpans(masks)), RedactedPlaceholder)
		if next == value {
			break
		}
		value = next
	}
	return value
}

// chainReading is the ranges of text one reading masks.
func chainReading(text string, ordered bool) []Span {
	cur := text
	origin := make([]Span, len(text))
	for i := range origin {
		origin[i] = Span{i, i + 1}
	}
	var holes []Span // the ranges placeholders took, empty ones too
	mask := func(runs []Span) {
		var next strings.Builder
		var nextOrigin []Span
		at := 0
		for _, run := range runs {
			next.WriteString(cur[at:run.Start])
			nextOrigin = append(nextOrigin, origin[at:run.Start]...)
			from := 0
			if run.Start > 0 {
				from = origin[run.Start-1].End
			}
			if run.Start < len(origin) {
				from = min(from, origin[run.Start].Start)
				if run.Start == run.End {
					from = origin[run.Start].Start
				}
			}
			to := from
			for i := run.Start; i < run.End; i++ {
				to = max(to, origin[i].End)
			}
			holes = append(holes, Span{from, to})
			next.WriteString(RedactedPlaceholder)
			for range len(RedactedPlaceholder) {
				nextOrigin = append(nextOrigin, Span{from, to})
			}
			at = run.End
		}
		next.WriteString(cur[at:])
		cur, origin = next.String(), append(nextOrigin, origin[at:]...)
	}
	ruleMasks := func(rule *compiledRule) []Span {
		var spans []Span
		for _, match := range rule.re.FindAllStringSubmatchIndex(cur, -1) {
			spans = append(spans, rule.masked(cur, match))
		}
		return spans
	}
	for pass := 0; pass < maxPasses; pass++ {
		before := cur
		if runs := settledRuns(cur, mergeSpans(commandSpans(cur))); ordered && len(runs) > 0 {
			mask(runs)
		}
		if ordered {
			for index := range compiledValueRules {
				if runs := settledRuns(cur, mergeSpans(ruleMasks(&compiledValueRules[index]))); len(runs) > 0 {
					mask(runs)
				}
			}
		} else {
			spans := commandSpans(cur)
			for index := range compiledValueRules {
				spans = append(spans, ruleMasks(&compiledValueRules[index])...)
			}
			if runs := settledRuns(cur, mergeSpans(spans)); len(runs) > 0 {
				mask(runs)
			}
		}
		if cur == before {
			break
		}
	}
	if cur == text {
		return nil
	}
	return holes
}

// redactionSamples are the coverage vectors' inputs, in other cases and
// with letters Unicode folds to ASCII ones, one after another so rules meet
// what earlier rules wrote, and prose no rule should touch.
func redactionSamples(t testing.TB) []string {
	t.Helper()
	var vectors coverageVectors
	loadTestdata(t, "redaction-coverage-vectors.json", &vectors)
	folds := strings.NewReplacer("s", "\u017f", "S", "\u017f", "k", "\u212a", "K", "\u212a")
	var samples, inputs []string
	for _, vector := range vectors.ValueVectors {
		inputs = append(inputs, vector.Input)
		samples = append(samples, vector.Input, strings.ToUpper(vector.Input), strings.ToLower(vector.Input), folds.Replace(vector.Input),
			"x"+vector.Input+"x", vector.Input+"\n"+vector.Input, strings.ReplaceAll(vector.Input, " ", "\n"))
	}
	for _, separator := range []string{"\n", " ", "", "; ", "\r\n"} {
		samples = append(samples, strings.Join(inputs, separator))
	}
	return append(samples,
		"", "plain text", "--- PASS: TestThing (0.00s)", "BYPASS=true deploy", "pip install basic package",
		"see the basic auth docs", RedactedPlaceholder, RedactedPlaceholder+"=value", "\xff\xfe invalid \xc5 bytes \xe2\x84",
		"Bearer \u212a\u017f12345678", "\u017fk-proj-FAKEabcdefghijklmnop1234", "PA\u017f\u017fWORD=x",
	)
}

func TestRedactTextMatchesTheRuleChain(t *testing.T) {
	t.Parallel()

	for _, sample := range redactionSamples(t) {
		redacted, changed := RedactText(sample)
		if want := ruleChain(sample); redacted != want || changed != (want != sample) {
			t.Fatalf("RedactText(%q) = %q, %v; the rule chain gives %q", sample, redacted, changed, want)
		}
	}
}

func TestRedactedSpansCoverTheSecrets(t *testing.T) {
	t.Parallel()

	var vectors coverageVectors
	loadTestdata(t, "redaction-coverage-vectors.json", &vectors)
	for _, vector := range vectors.ValueVectors {
		spans := RedactedSpans(vector.Input)
		if len(spans) == 0 {
			t.Fatalf("no spans in %q", vector.Input)
		}
		kept := keptText(vector.Input, spans, "\x00")
		for _, secret := range vector.MustNotSurvive {
			if strings.Contains(kept, secret) {
				t.Fatalf("secret %q survives the spans of %q: %q", secret, vector.Input, kept)
			}
		}
	}
}

func TestRedactedSpansAreWhatRedactTextRemoves(t *testing.T) {
	t.Parallel()

	for _, sample := range redactionSamples(t) {
		checkStretches(t, sample)
	}
}

func FuzzRedaction(f *testing.F) {
	for _, sample := range redactionSamples(f) {
		f.Add(sample)
	}
	f.Fuzz(func(t *testing.T, sample string) {
		if redacted, _ := RedactText(sample); redacted != ruleChain(sample) {
			t.Fatalf("RedactText(%q) = %q, the rule chain gives %q", sample, redacted, ruleChain(sample))
		}
		checkStretches(t, sample)
		checkNeedles(t, sample)
	})
}

// checkStretches checks that redact accounts for every byte of its result:
// each stretch from the sample holds the sample's bytes, in order, and
// RedactedSpans are the sample's bytes no stretch holds.
func checkStretches(t *testing.T, sample string) {
	t.Helper()
	redacted, stretches, _ := redact(sample, true)
	at, from := 0, 0
	for _, s := range stretches {
		if s.len <= 0 || at+s.len > len(redacted) {
			t.Fatalf("%q: bad stretch %+v at %d of %d", sample, s, at, len(redacted))
		}
		if s.from >= 0 {
			if s.from < from || redacted[at:at+s.len] != sample[s.from:s.from+s.len] {
				t.Fatalf("%q: stretch %+v does not hold the sample's bytes", sample, s)
			}
			from = s.from + s.len
		}
		at += s.len
	}
	if at != len(redacted) {
		t.Fatalf("%q: stretches cover %d of %d bytes", sample, at, len(redacted))
	}
	spans := RedactedSpans(sample)
	for i, span := range spans {
		if span.Start >= span.End || i > 0 && span.Start <= spans[i-1].End || span.End > len(sample) {
			t.Fatalf("%q: bad spans %v", sample, spans)
		}
	}
	// The sample with its spans removed is the sample's bytes in the
	// redacted text, in order.
	var kept strings.Builder
	at = 0
	for _, s := range stretches {
		if s.from >= 0 {
			kept.WriteString(redacted[at : at+s.len])
		}
		at += s.len
	}
	if got := keptText(sample, spans, ""); got != kept.String() {
		t.Fatalf("%q: outside its spans %q, RedactText keeps %q", sample, got, kept.String())
	}
}

// keptText is text with each span replaced by mark.
func keptText(text string, spans []Span, mark string) string {
	var out strings.Builder
	at := 0
	for _, span := range spans {
		out.WriteString(text[at:span.Start])
		out.WriteString(mark)
		at = span.End
	}
	out.WriteString(text[at:])
	return out.String()
}
