package riskclassifier

import (
	"strings"
	"sync"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

// A very long command must still store its redacted prefix, whatever redactor it
// is given. This deliberately injects risk.RedactCredentials, the harshest one in
// the tree: past a size limit it replaces its entire input with a placeholder,
// which is right for the 240-byte display summary it exists for and ruinous here,
// since every oversized script would store the same text and hash to the same
// value. Production wires the shared ruleset instead, which has no such limit —
// this proves the input cap protects the evidence field even if that changes.
func TestOversizedCommandsStayDistinguishable(t *testing.T) {
	var mu sync.Mutex
	var largestInput int
	collector := &recordCollector{}
	svm, err := LoadSVM()
	if err != nil {
		t.Fatalf("load svm: %v", err)
	}
	observer := NewObserver(ObserverOptions{
		SVM:  svm,
		Sink: collector.sink,
		Redact: func(value string) string {
			mu.Lock()
			if len(value) > largestInput {
				largestInput = len(value)
			}
			mu.Unlock()
			return risk.RedactCredentials(value)
		},
	})
	if observer == nil {
		t.Fatal("observer construction failed")
	}
	t.Cleanup(observer.Close)

	// Well past the redactor's oversized limit, differing only in a prefix that
	// has to survive into the row.
	filler := strings.Repeat("echo padding; ", 12000)
	first := "echo alpha-marker; " + filler
	second := "echo beta-marker; " + filler
	if len(first) < 128<<10 {
		t.Fatalf("test input too small to exercise the limit: %d bytes", len(first))
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
		if strings.Contains(record.Command, "exceeds summary limit") {
			t.Fatalf("%s collapsed into the oversized placeholder: %q", id, record.Command)
		}
		if !record.CommandTruncated {
			t.Errorf("%s should be marked truncated", id)
		}
		if len(record.Command) > storedCommandMaxBytes {
			t.Errorf("%s stored %d bytes, cap is %d", id, len(record.Command), storedCommandMaxBytes)
		}
	}
	if !strings.Contains(one.Command, "alpha-marker") || !strings.Contains(two.Command, "beta-marker") {
		t.Errorf("distinguishing prefix lost:\n%q\n%q", one.Command[:40], two.Command[:40])
	}
	if one.CommandHash == two.CommandHash {
		t.Error("two different long commands share a hash")
	}

	mu.Lock()
	defer mu.Unlock()
	if largestInput > redactionInputMaxBytes {
		t.Errorf("redactor was handed %d bytes, cap is %d", largestInput, redactionInputMaxBytes)
	}
}
