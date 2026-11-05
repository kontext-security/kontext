package riskclassifier_test

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
)

func TestAWSOperationReferenceReplay(t *testing.T) {
	m, err := riskclassifier.LoadOperationModel()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("testdata/aws-operations-golden.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 65536), 2*1024*1024)
	count := 0
	for s.Scan() {
		var row struct {
			Command string  `json:"command"`
			Score   float64 `json:"score"`
			Verdict string  `json:"verdict"`
			Count   int     `json:"count"`
		}
		if err := json.Unmarshal(s.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		got := m.Classify(row.Command)
		// The Python prototype visits function AST bodies more than once. Its
		// duplicate identical effects do not change the maximum score. Compare
		// the serving contract (margin/verdict), not that traversal artifact.
		if got.Score == nil {
			t.Errorf("fixture %d: no score, status %s", count, got.Status)
		} else if math.Abs(*got.Score-row.Score) > 1e-10 || got.Verdict != row.Verdict || got.OperationCount == 0 {
			t.Errorf("fixture %d: score %g, expected %g; verdict %s, expected %s", count, *got.Score, row.Score, got.Verdict, row.Verdict)
		}
		count++
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if count < 100 {
		t.Fatalf("reference corpus too small: %d", count)
	}
}

func TestAWSOperationExecutionContexts(t *testing.T) {
	m, err := riskclassifier.LoadOperationModel()
	if err != nil {
		t.Fatal(err)
	}
	aws := `aws secretsmanager get-secret-value --secret-id fixture`
	cases := []struct {
		name, command string
		risky         bool
		status        string
	}{
		{"direct", aws, true, "evaluated"},
		{"assignment", `VALUE=$(` + aws + `)`, true, "evaluated"},
		{"wrapper", `env REGION=eu-west-1 /usr/bin/aws --profile fixture secretsmanager get-secret-value --secret-id fixture`, true, "evaluated"},
		{"nested-shell", `bash -c '` + aws + `'`, true, "evaluated"},
		{"quoted-example", `printf '%s' '` + aws + `'`, false, "unsupported"},
		{"dormant-function", `fetch() { ` + aws + `; }; echo ready`, false, "unsupported"},
		{"invoked-function", `fetch() { ` + aws + `; }; fetch`, true, "evaluated"},
		{"false-if", `if false; then ` + aws + `; fi`, false, "unsupported"},
		{"false-and", `false && ` + aws, false, "unsupported"},
		{"true-or", `true || ` + aws, false, "unsupported"},
		{"help", aws + ` help`, false, "unsupported"},
		{"skeleton", aws + ` --generate-cli-skeleton`, false, "unsupported"},
		{"quoted-heredoc", "cat <<'EOF'\n" + aws + "\nEOF", false, "unsupported"},
		{"substitution-in-heredoc", "cat <<EOF\n$(" + aws + ")\nEOF", true, "evaluated"},
		{"dynamic-service", `aws "$SERVICE" get-secret-value --secret-id fixture`, false, "unsupported"},
		{"malformed", aws + ` "`, false, "parse_error"},
		{"resource-limit", strings.Repeat(" ", 1024*1024+1) + aws, false, "limit_exceeded"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := m.Classify(c.command)
			if (got.Verdict == riskclassifier.VerdictRisky) != c.risky || got.Status != c.status {
				t.Fatalf("got %+v", got)
			}
			if c.status != "evaluated" && got.Score != nil {
				t.Fatal("abstention carries a misleading score")
			}
		})
	}
}

func BenchmarkAWSOperationClassifier(b *testing.B) {
	m, err := riskclassifier.LoadOperationModel()
	if err != nil {
		b.Fatal(err)
	}
	for _, command := range []string{`echo ready`, `VALUE=$(aws secretsmanager get-secret-value --secret-id fixture)`, strings.Repeat("# setup\n", 1000) + `aws sts get-caller-identity`} {
		b.Run(command[:min(len(command), 25)], func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				m.Classify(command)
			}
		})
	}
}
