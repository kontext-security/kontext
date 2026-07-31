package riskclassifier

import (
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

// newRedactingObserver mirrors production wiring: the shared ruleset applied to
// the whole command, with no size guard in front of it.
func newRedactingObserver(t *testing.T, collector *recordCollector) *Observer {
	t.Helper()
	svm, err := LoadSVM()
	if err != nil {
		t.Fatalf("load svm: %v", err)
	}
	observer := NewObserver(ObserverOptions{
		SVM:  svm,
		Sink: collector.sink,
		Redact: func(value string) string {
			redacted, _ := payloadcapture.RedactText(value)
			return redacted
		},
	})
	if observer == nil {
		t.Fatal("observer construction failed")
	}
	t.Cleanup(observer.Close)
	return observer
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
	collector := &recordCollector{}
	observer := newRedactingObserver(t, collector)

	// Positioned to begin just inside the stored prefix and end far past it, so
	// any clip-then-redact order breaks its final segment.
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

	observer.Observe(ObserveInput{ActionID: "act_1", SessionID: "sess_1", Command: command})
	record := collector.wait(t, 1)[0]

	tail := record.Command[max(0, len(record.Command)-90):]
	if strings.Contains(record.Command, "eyJ") {
		t.Errorf("stored evidence carries a JWT fragment; tail: %q", tail)
	}
	if !strings.Contains(record.Command, payloadcapture.RedactedPlaceholder) {
		t.Errorf("token was not redacted at all; tail: %q", tail)
	}
}

// Two very long commands must stay distinguishable. Nothing in the path may
// replace an oversized command wholesale: that would store the same text for
// every long script and collapse their hashes together.
func TestOversizedCommandsStayDistinguishable(t *testing.T) {
	collector := &recordCollector{}
	observer := newRedactingObserver(t, collector)

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

	observer.Observe(ObserveInput{ActionID: "act_1", SessionID: "sess_1", Command: first})
	observer.Observe(ObserveInput{ActionID: "act_2", SessionID: "sess_1", Command: second})

	records := collector.wait(t, 2)
	stored := map[string]Record{}
	for _, record := range records {
		stored[record.ActionID] = record
	}
	one, two := stored["act_1"], stored["act_2"]

	for id, record := range stored {
		if !record.CommandTruncated {
			t.Errorf("%s should be marked truncated", id)
		}
		if len(record.Command) > storedCommandMaxBytes {
			t.Errorf("%s stored %d bytes, cap is %d", id, len(record.Command), storedCommandMaxBytes)
		}
		if record.SVM == nil {
			t.Errorf("%s lost its verdict", id)
		}
	}
	if !strings.Contains(one.Command, "alpha-marker") || !strings.Contains(two.Command, "beta-marker") {
		t.Errorf("distinguishing prefix lost:\n%q\n%q", one.Command[:40], two.Command[:40])
	}
	if one.CommandHash == two.CommandHash {
		t.Error("two different long commands share a hash")
	}
}
