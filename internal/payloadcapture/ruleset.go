package payloadcapture

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// RedactedPlaceholder replaces every redacted key value and pattern match.
const RedactedPlaceholder = "[REDACTED_SECRET]"

// ruleset.json is a mirror of the shared redaction ruleset artifact. Patterns
// are RE2-safe and replacements use $n capture expansion by contract so the
// same file drives every engine; do not edit it independently of the source
// artifact.
//
//go:embed ruleset.json
var rulesetJSON []byte

type redactionRule struct {
	ID              string `json:"id"`
	Description     string `json:"description"`
	Pattern         string `json:"pattern"`
	Replacement     string `json:"replacement"`
	CaseInsensitive bool   `json:"caseInsensitive"`
	Provenance      string `json:"provenance"`
}

type redactionRuleset struct {
	Version          string          `json:"version"`
	KeyNormalization string          `json:"keyNormalization"`
	KeyPatterns      []redactionRule `json:"keyPatterns"`
	ValuePatterns    []redactionRule `json:"valuePatterns"`
}

type compiledRule struct {
	id          string
	re          *regexp.Regexp
	replacement string
	// pieces is the replacement split into text and the capture groups it
	// copies; groups is set when it copies any but the whole match.
	pieces []piece
	groups bool
	// needles, when filtered, are strings of which every match contains one
	// (see needles.go).
	needles  []string
	filtered bool
}

var (
	// RedactorVersion identifies the ruleset that produced redacted bytes.
	// It is reported on every captured payload record and always comes from
	// the embedded artifact, never from a separate constant.
	RedactorVersion string

	compiledKeyRules   []compiledRule
	compiledValueRules []compiledRule
	camelBoundary      = regexp.MustCompile(`([a-z])([A-Z])`)
)

func init() {
	var ruleset redactionRuleset
	if err := json.Unmarshal(rulesetJSON, &ruleset); err != nil {
		panic(fmt.Sprintf("payloadcapture: invalid embedded ruleset: %v", err))
	}
	if ruleset.KeyNormalization != "camel_to_snake" {
		panic(fmt.Sprintf(
			"payloadcapture: unsupported key normalization %q",
			ruleset.KeyNormalization,
		))
	}

	RedactorVersion = ruleset.Version
	compiledKeyRules = compileRules(ruleset.KeyPatterns)
	compiledValueRules = compileRules(ruleset.ValuePatterns)
}

func compileRules(rules []redactionRule) []compiledRule {
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		pattern := rule.Pattern
		if rule.CaseInsensitive {
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			panic(fmt.Sprintf(
				"payloadcapture: rule %q does not compile: %v",
				rule.ID, err,
			))
		}
		replacement := rule.Replacement
		if replacement == "" {
			replacement = RedactedPlaceholder
		}
		if !strings.Contains(replacement, RedactedPlaceholder) {
			panic(fmt.Sprintf(
				"payloadcapture: rule %q replacement omits redaction placeholder",
				rule.ID,
			))
		}
		if strings.Contains(replacement, "\x00") {
			panic(fmt.Sprintf(
				"payloadcapture: rule %q replacement contains a NUL byte",
				rule.ID,
			))
		}
		split := pieces(re, replacement)
		set, filtered := needles(pattern)
		compiled = append(compiled, compiledRule{
			id:          rule.ID,
			re:          re,
			replacement: replacement,
			pieces:      split,
			groups:      slices.ContainsFunc(split, func(p piece) bool { return p.group > 0 }),
			needles:     set,
			filtered:    filtered,
		})
	}
	return compiled
}

func isSensitiveKey(key string) bool {
	normalized := camelBoundary.ReplaceAllString(key, "${1}_${2}")
	for _, rule := range compiledKeyRules {
		if rule.re.MatchString(normalized) {
			return true
		}
	}
	return false
}

// RedactText runs the ruleset's value patterns over a flat string, applies
// their replacement templates, and reports whether anything changed. Every
// replacement contains RedactedPlaceholder; some preserve structural capture
// groups such as a header label or query delimiter. Key patterns do not apply:
// a flat string carries no structure to classify.
func RedactText(value string) (string, bool) {
	redacted, _, changed := redact(value, false)
	return redacted, changed
}
