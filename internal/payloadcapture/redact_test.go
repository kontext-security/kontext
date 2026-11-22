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
		// An @ in a path or an scp-style remote is not URL userinfo.
		"curl https://unpkg.com/react@18.3.1/umd/react.js",
		"curl http://localhost:5173/@vite/client",
		"git clone git@github.com:org/repo.git",
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

	// rules/4: a program's password-flag rules run before
	// sensitive-assignment by contract, which would otherwise read a prompt
	// text such as `sshpass -P password:` as a key and swallow the -p after
	// it. rules/5: json-sensitive-property runs before the vendor token rules
	// by contract, so a property named like a token (`"glpat-…": "…"`) loses
	// its value rather than only its name. Their vectors hold in the ruleset's
	// order only.
	ordered := func(ruleID, name string) bool {
		return strings.HasPrefix(ruleID, "mysql-") || strings.HasPrefix(ruleID, "sshpass-") || strings.HasPrefix(ruleID, "redis-cli-") ||
			name == "gitlab-named-json-property"
	}
	for _, vector := range vectors.ValueVectors {
		orders := [][]compiledRule{compiledValueRules, reversed}
		if ordered(vector.RuleID, vector.Name) {
			orders = orders[:1]
		}
		for _, order := range orders {
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

func TestHasSecretTokenReadsTokenShapesOnly(t *testing.T) {
	t.Parallel()
	for _, token := range []string{
		"glpat-FAKE0123456789abcdefgh",
		"ciglpat-FAKE0123456789abcdefgh",
		"ghp_FAKE0123456789abcdefFAKE",
		"sk_live_" + strings.Repeat("x", 28),
		"SG." + strings.Repeat("x", 22) + "." + strings.Repeat("x", 43),
		"eyJ1c2VyIjo0Mn0.FAKEsignatureFAKEabc",
		"key_ASIA" + "FAKE0123456789AB_ci",
	} {
		if !HasSecretToken(token) {
			t.Fatalf("%q is not a token", token)
		}
	}
	for _, plain := range []string{
		"--password hunter2", "token=abc", "deploy-check", "1.4.0",
		"pypi-attestations", "task_test_environment", "hf_imageclassification.py", "SG.SecurityGroupIngress",
		"SG.SecurityGroupIngress.SourceSecurityGroupId", "keyJsonSchema.properties.type",
		"publicKeyJsonConverter.test.js", "libxapp/xapp-status-icon-monitor.h",
		"cache/eyJwYWdlIjoxfQ.json", "docs/glimt-incoming-mail-settings.md",
		"network_org_defaultNotificationSettings", "task_org_defaultNotificationSettings", "work_org_507f1f77bcf86cd799439011",
	} {
		if HasSecretToken(plain) {
			t.Fatalf("%q read as a token", plain)
		}
	}
}
