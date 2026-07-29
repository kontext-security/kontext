package payloadcapture

import (
	"regexp"
	"strings"
	"testing"
)

type coverageVectors struct {
	ValueVectors []struct {
		Name           string   `json:"name"`
		RuleID         string   `json:"ruleId"`
		Input          string   `json:"input"`
		MustNotSurvive []string `json:"mustNotSurvive"`
		Expected       string   `json:"expected"`
	} `json:"valueVectors"`
	KeyVectors []struct {
		Name      string `json:"name"`
		Key       string `json:"key"`
		Sensitive bool   `json:"sensitive"`
	} `json:"keyVectors"`
}

func TestRulesetCompilesAndIsVersioned(t *testing.T) {
	t.Parallel()

	// Compilation itself is enforced by package init (a bad pattern panics
	// before any test runs); this pins the version format the capture
	// records report.
	if !regexp.MustCompile(`^rules/\d+$`).MatchString(RedactorVersion) {
		t.Fatalf("unexpected redactor version %q", RedactorVersion)
	}
	if len(compiledKeyRules) == 0 || len(compiledValueRules) == 0 {
		t.Fatal("ruleset compiled empty")
	}
}

func TestRedactionCoverage(t *testing.T) {
	t.Parallel()

	var vectors coverageVectors
	loadTestdata(t, "redaction-coverage-vectors.json", &vectors)
	if len(vectors.ValueVectors) == 0 || len(vectors.KeyVectors) == 0 {
		t.Fatal("no coverage vectors loaded")
	}

	covered := map[string]bool{}
	for _, vector := range vectors.ValueVectors {
		covered[vector.RuleID] = true
	}
	for _, rule := range compiledValueRules {
		if !covered[rule.id] {
			t.Errorf("value rule %q has no coverage vector", rule.id)
		}
	}

	for _, vector := range vectors.ValueVectors {
		t.Run(vector.Name, func(t *testing.T) {
			t.Parallel()

			redacted, changed := RedactText(vector.Input)
			if !changed {
				t.Fatalf("input was not redacted: %q", vector.Input)
			}
			for _, secret := range vector.MustNotSurvive {
				if strings.Contains(redacted, secret) {
					t.Fatalf("secret survived redaction: %q in %q", secret, redacted)
				}
			}
			if !strings.Contains(redacted, RedactedPlaceholder) {
				t.Fatalf("placeholder missing from %q", redacted)
			}
			if vector.Expected != "" && redacted != vector.Expected {
				t.Fatalf("redacted = %q, want %q", redacted, vector.Expected)
			}
		})
	}

	for _, vector := range vectors.KeyVectors {
		t.Run("key/"+vector.Name, func(t *testing.T) {
			t.Parallel()

			if got := isSensitiveKey(vector.Key); got != vector.Sensitive {
				t.Fatalf("isSensitiveKey(%q) = %v, want %v", vector.Key, got, vector.Sensitive)
			}
		})
	}
}

// TestRedactTextLeavesProseAlone pins false-positive boundaries: a short
// word after "basic" is prose (Authorization-header context redacts Basic
// values at any length), and pwd/pass only classify a key when they form a
// complete _/- delimited segment of its name.
func TestRedactTextLeavesProseAlone(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"pip install basic package",
		"see the basic auth docs",
		"BYPASS=true deploy",
		"OLDPWD=/home/user ls",
		"COMPASS=north run",
	} {
		redacted, changed := RedactText(input)
		if changed || redacted != input {
			t.Fatalf("prose was redacted: %q -> %q", input, redacted)
		}
	}
}

// TestRedactionCoverageIsOrderIndependent guards the coverage invariant
// against rule interference: an earlier rule's placeholder substitution must
// not prevent a later rule from catching its secret, regardless of the order
// rules run in.
func TestRedactionCoverageIsOrderIndependent(t *testing.T) {
	t.Parallel()

	var vectors coverageVectors
	loadTestdata(t, "redaction-coverage-vectors.json", &vectors)

	apply := func(rules []compiledRule, input string) string {
		for _, rule := range rules {
			input = rule.re.ReplaceAllString(input, rule.replacement)
		}
		return input
	}

	reversed := make([]compiledRule, len(compiledValueRules))
	for index, rule := range compiledValueRules {
		reversed[len(reversed)-1-index] = rule
	}

	for _, vector := range vectors.ValueVectors {
		for _, order := range [][]compiledRule{compiledValueRules, reversed} {
			redacted := apply(order, vector.Input)
			for _, secret := range vector.MustNotSurvive {
				if strings.Contains(redacted, secret) {
					t.Fatalf("secret %q survived under rule order variation in %s", secret, vector.Name)
				}
			}
		}
	}
}

func TestRedactJSONDoesNotMutateInput(t *testing.T) {
	t.Parallel()

	input := map[string]any{
		"apiKey": "raw-secret-value",
		"nested": map[string]any{"command": "GITHUB_TOKEN=leaked gh api"},
	}

	redacted, changed := RedactJSON(input)
	if !changed {
		t.Fatal("expected redaction changes")
	}
	if input["apiKey"] != "raw-secret-value" {
		t.Fatal("input map was mutated")
	}
	if redacted["apiKey"] != RedactedPlaceholder {
		t.Fatalf("sensitive key not replaced: %v", redacted["apiKey"])
	}
}
