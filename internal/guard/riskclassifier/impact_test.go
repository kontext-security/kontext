package riskclassifier

import (
	"bufio"
	"context"
	"encoding/json"
	"math"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier/impactfeatures"
)

// The golden predictions come from the frozen research binary, not this port.
// Inputs are syntax data only. They are never passed to an operating-system shell.
func TestImpactFrozenResearchParity(t *testing.T) {
	m, err := LoadImpactModel()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("testdata/impact-golden.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 65536), 1024*1024)
	for s.Scan() {
		var row struct {
			ID       string `json:"id"`
			Command  string `json:"command"`
			Expected struct {
				Prediction struct {
					Status string   `json:"status"`
					Score  *float64 `json:"score"`
				} `json:"prediction"`
			} `json:"expected"`
		}
		if err := json.Unmarshal(s.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		t.Run(row.ID, func(t *testing.T) {
			got := m.Classify(row.Command)
			want := row.Expected.Prediction
			if got.Status != want.Status || got.Enforced || got.Threshold != ImpactThreshold || got.ModelSHA256 != ImpactModelSHA256 || got.ExtractorVersion != impactfeatures.Version {
				t.Fatalf("metadata mismatch: %+v", got)
			}
			if want.Score == nil {
				if got.Score != nil || got.Verdict != "not_assessed" {
					t.Fatalf("limit treated as assessed: %+v", got)
				}
				return
			}
			if got.Score == nil || math.Abs(*got.Score-*want.Score) > 1e-12 {
				t.Fatalf("score = %v; frozen = %v", got.Score, want.Score)
			}
			wantVerdict := "below_threshold"
			if *want.Score >= ImpactThreshold {
				wantVerdict = "flagged"
			}
			if got.Verdict != wantVerdict {
				t.Fatalf("verdict = %s, want %s", got.Verdict, wantVerdict)
			}
		})
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestImpactIndependentShellAnnotationAndFailure(t *testing.T) {
	svm, err := LoadSVM()
	if err != nil {
		t.Fatal(err)
	}
	m, err := LoadImpactModel()
	if err != nil {
		t.Fatal(err)
	}
	c := NewClassifier(ClassifierOptions{SVM: svm, Impact: m, Redact: func(s string) string { return s }})
	for _, tool := range []string{"Bash", "exec_command", "functions.exec_command", "unified_exec", "local_shell", " LOCAL_SHELL "} {
		v := c.Classify(context.Background(), "session", tool, `pkill -f "apps/web/server.js"`)
		if v.Impact == nil || v.Impact.Verdict != "flagged" {
			t.Fatalf("%s missing independent impact flag: %+v", tool, v)
		}
		if v.SVM == nil || v.SVM.Verdict == VerdictRisky {
			t.Fatalf("fixture must exercise an Impact-only alert: %+v", v)
		}
	}
	for _, tool := range []string{"apply_patch", "Read", "mcp__search", "powershell", "pwsh", "not_a_shell"} {
		if c.Classify(context.Background(), "session", tool, "pkill -x unbound").Impact != nil {
			t.Fatalf("non-shell %s classified", tool)
		}
	}
	broken := NewClassifier(ClassifierOptions{SVM: svm, ImpactError: true, Redact: func(s string) string { return s }})
	v := broken.Classify(context.Background(), "session", "Bash", "printf ready")
	if v.SVM == nil || v.Impact == nil || v.Impact.Status != "model_unavailable" || v.Impact.Score != nil || v.Impact.Enforced {
		t.Fatalf("failure disabled existing model or invented score: %+v", v)
	}
	if err := validateImpactModel([]byte("{}")); err == nil {
		t.Fatal("invalid artifact accepted")
	}
}

func TestImpactConcurrentDeterminism(t *testing.T) {
	m, err := LoadImpactModel()
	if err != nil {
		t.Fatal(err)
	}
	command := "pkill -x unbound"
	want := m.Classify(command)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for range 5 {
				got := m.Classify(command)
				if got.Score == nil || *got.Score != *want.Score || got.Verdict != want.Verdict {
					t.Errorf("non-deterministic score: %+v", got)
				}
			}
		})
	}
	wg.Wait()
}

func TestImpactScoresFullInputButStoresRedactedPrefix(t *testing.T) {
	svm, _ := LoadSVM()
	m, _ := LoadImpactModel()
	c := NewClassifier(ClassifierOptions{SVM: svm, Impact: m, Redact: func(s string) string { return strings.ReplaceAll(s, "fixture-secret-value", "[REDACTED]") }})
	command := "# fixture-secret-value\n" + strings.Repeat("# ordinary context\n", 600) + "pkill -x unbound"
	v := c.Classify(context.Background(), "session", "Bash", command)
	want := m.Classify(command)
	if !v.CommandTruncated || strings.Contains(v.Command, "fixture-secret-value") || len(v.Command) > storedCommandMaxBytes {
		t.Fatal("stored command not redacted/capped")
	}
	if v.Impact == nil || v.Impact.Score == nil || *v.Impact.Score != *want.Score {
		t.Fatal("inference used stored prefix instead of full command")
	}
}
