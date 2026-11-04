package payloadcapture

import (
	"math/rand/v2"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// checkNeedles checks that a rule never skips a text it matches.
func checkNeedles(t *testing.T, sample string) {
	t.Helper()
	folded := fold(sample)
	for _, rule := range compiledValueRules {
		if rule.filtered && rule.re.MatchString(sample) && !containsAny(folded, rule.needles) {
			t.Fatalf("%s matches %q, which holds none of its needles %q", rule.id, sample, rule.needles)
		}
	}
}

func TestNeedlesNeverSkipAMatch(t *testing.T) {
	t.Parallel()

	for _, sample := range redactionSamples(t) {
		checkNeedles(t, sample)
	}
}

// Every value rule has needles, so a text holding none of them costs a few
// searches for fixed strings, not a run of every pattern.
func TestRulesetNeedles(t *testing.T) {
	t.Parallel()

	want := map[string][]string{
		"github-token":        {"gho_", "ghp_", "ghr_", "ghs_", "ghu_"},
		"aws-access-key-id":   {"akia", "asia"},
		"openai-api-key":      {"sk-"},
		"url-userinfo":        {"://"},
		"basic-auth-userinfo": {"-u"},
	}
	for _, rule := range compiledValueRules {
		if !rule.filtered || len(rule.needles) == 0 {
			t.Errorf("%s has no needles", rule.id)
		}
		if needles, pinned := want[rule.id]; pinned && !slices.Equal(rule.needles, needles) {
			t.Errorf("%s needles = %q, want %q", rule.id, rule.needles, needles)
		}
	}
}

func TestNeedlesOfPatterns(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		pattern string
		needles []string // nil: none
	}{
		{`abc`, []string{"abc"}},
		{`(?i)AbC`, []string{"abc"}},
		{`a|bc`, []string{"a", "bc"}},
		{`x*`, nil},
		{`x+y`, []string{"x"}},
		{`(?:ab)+`, []string{"ab"}},
		{`a?b`, []string{"b"}},
		{`a[bc]d`, []string{"abd", "acd"}},
		{`\bfoo\b`, []string{"foo"}},
		{`[^a]`, nil},
		{`.`, nil},
		{`ab|c*`, nil},
		{`key[_-]?id`, []string{"keyid", "key-id", "key_id"}},
		{`(?:--|-)u`, []string{"-u"}},
		{`(?i)\x{e9}t\x{e9}`, nil},
		{`\x{e9}t\x{e9}`, []string{"\u00e9t\u00e9"}},
		{`\x{fffd}`, nil},
		{`[a-z]{2}@`, []string{"@"}},
	} {
		got, ok := needles(test.pattern)
		if ok != (test.needles != nil) || ok && !slices.Equal(got, test.needles) {
			t.Errorf("needles(%q) = %q, %v, want %q", test.pattern, got, ok, test.needles)
		}
	}
}

// Needles hold for patterns of any shape: no random text a random pattern
// matches lacks all of its needles.
func TestNeedlesHoldForRandomPatterns(t *testing.T) {
	t.Parallel()

	random := rand.New(rand.NewPCG(1, 2))
	atoms := []string{"a", "b", "ab", "(?i:k)", "s", "[ab]", "[^a]", ".", `\b`, "^", "$", "x"}
	alphabet := []string{"a", "b", "A", "B", "k", "K", "\u212a", "s", "\u017f", "S", "x", " ", "\n"}
	var build func(depth int) string
	build = func(depth int) string {
		if depth == 0 {
			return atoms[random.IntN(len(atoms))]
		}
		switch random.IntN(6) {
		case 0:
			return build(depth-1) + "|" + build(depth-1)
		case 1:
			return "(?:" + build(depth-1) + ")*"
		case 2:
			return "(?:" + build(depth-1) + ")+"
		case 3:
			return "(?:" + build(depth-1) + ")?"
		case 4:
			return "(?i:" + build(depth-1) + ")"
		}
		return "(?:" + build(depth-1) + ")(?:" + build(depth-1) + ")"
	}
	for range 2000 {
		pattern := build(3)
		re := regexp.MustCompile(pattern)
		set, ok := needles(pattern)
		if !ok {
			continue
		}
		for range 50 {
			var text strings.Builder
			for range random.IntN(12) {
				text.WriteString(alphabet[random.IntN(len(alphabet))])
			}
			if re.MatchString(text.String()) && !containsAny(fold(text.String()), set) {
				t.Fatalf("%q matches %q, which holds none of its needles %q", pattern, text.String(), set)
			}
		}
	}
}

func TestFold(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"":                            "",
		"already lower":               "already lower",
		"MiXeD":                       "mixed",
		"\u017fK\u212a":               "skk",
		"caf\u00c9 \xff\xc5 \xe2\x84": "caf\u00c9 \xff\xc5 \xe2\x84",
	} {
		if got := fold(in); got != want {
			t.Errorf("fold(%q) = %q, want %q", in, got, want)
		}
	}
}
