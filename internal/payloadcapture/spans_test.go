package payloadcapture

import (
	"strings"
	"testing"
)

// ruleChain is RedactText without needles: every value pattern run over the
// whole text, in order.
func ruleChain(value string) string {
	for _, rule := range compiledValueRules {
		value = rule.re.ReplaceAllString(value, rule.replacement)
	}
	return value
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

func TestPiecesFollowExpand(t *testing.T) {
	t.Parallel()

	for _, rule := range compiledValueRules {
		for _, sample := range redactionSamples(t) {
			for _, match := range rule.re.FindAllStringSubmatchIndex(sample, -1) {
				var got strings.Builder
				for _, p := range rule.pieces {
					if p.group < 0 {
						got.WriteString(p.text)
					} else if match[2*p.group] >= 0 {
						got.WriteString(sample[match[2*p.group]:match[2*p.group+1]])
					}
				}
				if want := string(rule.re.ExpandString(nil, rule.replacement, sample, match)); got.String() != want {
					t.Fatalf("%s: pieces give %q, Expand %q", rule.id, got.String(), want)
				}
			}
		}
	}
}
