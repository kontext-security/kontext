package riskclassifier

import (
	"context"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

// newRedactingClassifier mirrors production wiring: the shared ruleset applied to
// the whole command, with no size guard in front of it.
func newRedactingClassifier(t *testing.T) *Classifier {
	t.Helper()
	svm, err := LoadSVM()
	if err != nil {
		t.Fatalf("load svm: %v", err)
	}
	classifier := NewClassifier(ClassifierOptions{
		SVM: svm,
		Redact: func(value string) string {
			redacted, _ := payloadcapture.RedactText(value)
			return redacted
		},
	})
	if classifier == nil {
		t.Fatal("classifier construction failed")
	}
	return classifier
}

// A credential must be redacted even when it straddles the truncation boundary.
// Several rules are structural: the JWT pattern requires all three dot-separated
// segments, so redacting a clipped prefix stops matching a token whose tail falls
// past the cut and stores its head verbatim. This is why the whole command is
// redacted before anything is truncated.
//
// The token here carries no Authorization or Bearer prefix on purpose. Those have
// their own rules that would redact it regardless of the JWT pattern and hide the
// very failure being guarded against.
func TestCredentialStraddlingTheStoreCapIsStillRedacted(t *testing.T) {
	classifier := newRedactingClassifier(t)

	header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	token := header + "." + strings.Repeat("QWxhZGRpbjpvcGVuc2VzYW1l", 700) + ".c2lnbmF0dXJlX3ZhbHVl"
	command := "echo " + strings.Repeat("y", storedCommandMaxBytes-100) + " " + token + " >/dev/null"
	tokenStart := strings.Index(command, header)
	if tokenStart >= storedCommandMaxBytes {
		t.Fatalf("token starts at %d, must begin inside the %d-byte stored prefix", tokenStart, storedCommandMaxBytes)
	}
	if tokenStart+len(token) <= 2*storedCommandMaxBytes {
		t.Fatalf("token ends at %d, must extend past any plausible clip point", tokenStart+len(token))
	}

	verdicts := classifier.Classify(context.Background(), "sess_1", command)
	tail := verdicts.Command[max(0, len(verdicts.Command)-90):]
	if strings.Contains(verdicts.Command, "eyJ") {
		t.Errorf("stored evidence carries a JWT fragment; tail: %q", tail)
	}
	if !strings.Contains(verdicts.Command, payloadcapture.RedactedPlaceholder) {
		t.Errorf("token was not redacted at all; tail: %q", tail)
	}
}

// Two very long commands must stay distinguishable. Nothing in the path may
// replace an oversized command wholesale: that would keep the same text for
// every long script and collapse their hashes together.
func TestOversizedCommandsStayDistinguishable(t *testing.T) {
	classifier := newRedactingClassifier(t)

	// Just over 64 KiB: past the size at which the strict redactor gives up, which
	// is the limit worth guarding against, and no larger. Redaction is linear in
	// length and these run under -race in CI, so an input several times bigger
	// buys no coverage and costs seconds.
	filler := strings.Repeat("echo padding; ", 5000)
	first := "echo alpha-marker; " + filler
	second := "echo beta-marker; " + filler
	if len(first) < 64<<10 {
		t.Fatalf("test input too small: %d bytes", len(first))
	}

	one := classifier.Classify(context.Background(), "sess_1", first)
	two := classifier.Classify(context.Background(), "sess_1", second)

	for label, verdicts := range map[string]Verdicts{"first": one, "second": two} {
		if !verdicts.CommandTruncated {
			t.Errorf("%s should be marked truncated", label)
		}
		if len(verdicts.Command) > storedCommandMaxBytes {
			t.Errorf("%s kept %d bytes, cap is %d", label, len(verdicts.Command), storedCommandMaxBytes)
		}
		if verdicts.SVM == nil {
			t.Errorf("%s lost its verdict", label)
		}
	}
	if !strings.Contains(one.Command, "alpha-marker") || !strings.Contains(two.Command, "beta-marker") {
		t.Errorf("distinguishing prefix lost:\n%q\n%q", one.Command[:40], two.Command[:40])
	}
	if one.CommandHash == two.CommandHash {
		t.Error("two different long commands share a hash")
	}
}
