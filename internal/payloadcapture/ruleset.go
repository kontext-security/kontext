package payloadcapture

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
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
	CommandRules     commandRuleset  `json:"commandRules"`
}

type compiledRule struct {
	id          string
	re          *regexp.Regexp
	replacement string
	// before and after are the replacement's parts around the placeholder:
	// what a match keeps of its start (capture groups and text) and of its
	// end (text). groups is set when before copies a capture group.
	before, after string
	groups        bool
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
	// tokenRules are the value rules that read a token's own shape; the
	// structural ones read its context.
	tokenRules    []tokenRule
	camelBoundary = regexp.MustCompile(`([a-z])([A-Z])`)
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
	if ruleset.CommandRules.MaxDepth <= 0 || len(ruleset.CommandRules.Programs) == 0 {
		panic("payloadcapture: embedded ruleset has no command rules")
	}
	compileCommandRules(ruleset.CommandRules)
	for index, rule := range ruleset.ValuePatterns {
		if rule.Provenance != "structural" {
			tokenRules = append(tokenRules, tokenRule{compiledValueRules[index].re, tokenRuleNeeds[rule.ID]})
		}
	}
}

// tokenRule is a token rule HasSecretToken scans only when the value
// holds needs (when set).
type tokenRule struct {
	re    *regexp.Regexp
	needs string
}

// tokenRuleNeeds is what a value must hold for a token rule to match where
// another one does not: gitlab-session-cookie-escaped differs from
// gitlab-session-cookie only in reading past an escaped ;, and skipping it
// otherwise saves a second scan of a run of cookie names.
var tokenRuleNeeds = map[string]string{"gitlab-session-cookie-escaped": `\;`}

// maxTokenScan is the longest value HasSecretToken scans; a longer one
// counts as a secret (fail closed). The cloud's JS RegExp backtracks where
// RE2 does not, so it stops there, and the agent matches it.
const maxTokenScan = 1024

// HasSecretToken reports a value that holds a known secret token shape (a
// vendor key, a JWT, a private key): the ruleset's value patterns that aren't
// structural. The structural ones read a value's context (`--password x`,
// `token=x`), which a caller that keeps only some words of a command line
// checks itself. Matches hasSecretToken in kontext-cloud's
// redaction-ruleset.ts.
func HasSecretToken(value string) bool {
	if len(value) > maxTokenScan {
		return true
	}
	for _, rule := range tokenRules {
		if (rule.needs == "" || strings.Contains(value, rule.needs)) && rule.re.MatchString(value) {
			return true
		}
	}
	return false
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
		before, after, _ := strings.Cut(replacement, RedactedPlaceholder)
		if strings.Contains(after, "$") {
			panic(fmt.Sprintf(
				"payloadcapture: rule %q replacement copies a group after the placeholder",
				rule.ID,
			))
		}
		set, filtered := needles(pattern)
		compiled = append(compiled, compiledRule{
			id:          rule.ID,
			re:          re,
			replacement: replacement,
			before:      before,
			after:       after,
			groups:      strings.Contains(before, "$"),
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
