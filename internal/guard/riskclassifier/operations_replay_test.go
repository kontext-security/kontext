package riskclassifier_test

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
)

// Optional private-corpus replay. Supply newline-delimited {id,command} inputs
// and a distinct output path. Output contains scores/status only, never command
// text, credentials or hashes of unredacted input. Commands remain inert data.
func TestAWSOperationLocalCorpusReplay(t *testing.T) {
	input, output := os.Getenv("KONTEXT_OPERATIONS_REPLAY_INPUT"), os.Getenv("KONTEXT_OPERATIONS_REPLAY_OUTPUT")
	if input == "" {
		t.Skip("set KONTEXT_OPERATIONS_REPLAY_INPUT and KONTEXT_OPERATIONS_REPLAY_OUTPUT for private corpus replay")
	}
	if output == "" || input == output {
		t.Fatal("a distinct output path is required")
	}
	m, err := riskclassifier.LoadOperationModel()
	if err != nil {
		t.Fatal(err)
	}
	svm, err := riskclassifier.LoadSVM()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out, err := os.OpenFile(output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	enc := json.NewEncoder(out)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 65536), 2*1024*1024)
	count := 0
	for scanner.Scan() {
		var row struct {
			ID      string `json:"id"`
			Command string `json:"command"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		verdict := m.Classify(row.Command)
		elapsed := time.Since(start).Nanoseconds()
		legacy := svm.Classify(row.Command)
		verdict.CombinedVerdict = legacy.Verdict
		if verdict.Verdict == riskclassifier.VerdictRisky {
			verdict.CombinedVerdict = riskclassifier.VerdictRisky
		}
		if err := enc.Encode(struct {
			ID         string                          `json:"id"`
			Legacy     riskclassifier.SVMVerdict       `json:"svm"`
			Operations riskclassifier.OperationVerdict `json:"operations"`
			ElapsedNS  int64                           `json:"elapsed_ns"`
		}{row.ID, legacy, verdict, elapsed}); err != nil {
			t.Fatal(err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("empty replay corpus")
	}
	t.Logf("scored %d inert inputs; receipt: %s", count, output)
}
