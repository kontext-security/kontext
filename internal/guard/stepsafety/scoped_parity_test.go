package stepsafety

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"
)

func TestScopedPythonNativeParity(t *testing.T) {
	path := os.Getenv("MERLIN_V3_PARITY_FIXTURE")
	if path == "" {
		path = "testdata/scoped_golden.json"
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var rows []struct {
		Name                 string
		Input                Input
		Fields               [4]string
		IDs                  []int64 `json:"input_ids"`
		Mask                 []int64 `json:"attention_mask"`
		Logits               [2]float64
		Probability          float64
		Unsafe               bool
		Error                string
		RequestIntent        *float64 `json:"request_intent_probability"`
		UncroppedTokenCounts [4]int   `json:"uncropped_token_counts"`
		HistoryOmitted       *bool    `json:"history_omitted"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if e = decoder.Decode(&rows); e != nil {
		t.Fatal(e)
	}
	// Use the same cold-start allowance as the other native parity tests;
	// race instrumentation is much slower while loading the checkpoint.
	b, e := newNativeBackend(context.Background(), normalizeConfig(Config{StartupTimeout: 2 * time.Minute}))
	if e != nil {
		t.Fatal(e)
	}
	maxLogit, maxScore := 0., 0.
	var cropCoverage [4]bool
	for _, r := range rows {
		t.Run(r.Name, func(t *testing.T) {
			before, _ := json.Marshal(r.Input)
			if r.RequestIntent != nil {
				if math.Abs(requestIntentProbability(r.Input.UserRequest)-*r.RequestIntent) > 1e-9 {
					t.Fatal("request intent score differs")
				}
			}
			packed, e := packScopedInput(context.Background(), b.tokenizer, r.Input)
			if r.Error != "" {
				if e == nil || errorCode(e) != r.Error {
					t.Fatalf("error=%v want=%s", e, r.Error)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			fields, e := candidateFields(r.Input)
			if e != nil || !reflect.DeepEqual(fields, r.Fields) {
				t.Fatalf("fields differ: %v\ngot=%q\nwant=%q", e, fields, r.Fields)
			}
			for i, field := range fields {
				ids, err := b.tokenizer.encode(context.Background(), field)
				if err != nil {
					t.Fatal(err)
				}
				if want := r.UncroppedTokenCounts[i]; want != 0 && len(ids) != want {
					t.Fatalf("field %d uncropped tokens=%d want=%d", i, len(ids), want)
				}
				cropCoverage[i] = cropCoverage[i] || len(ids) > fieldBudgets[i]
			}
			if !slices.Equal(packed.IDs, r.IDs) || !slices.Equal(packed.Mask, r.Mask) {
				t.Fatalf("Python/Go token mismatch")
			}
			if r.HistoryOmitted != nil && packed.HistoryOmitted != *r.HistoryOmitted {
				t.Fatalf("history omitted=%t want=%t", packed.HistoryOmitted, *r.HistoryOmitted)
			}
			result, e := b.Infer(context.Background(), r.Input)
			if e != nil {
				t.Fatal(e)
			}
			for i, x := range result.Logits {
				d := math.Abs(x - r.Logits[i])
				maxLogit = math.Max(maxLogit, d)
				if d > 1e-4 {
					t.Fatalf("logits=%v want=%v", result.Logits, r.Logits)
				}
			}
			score := CalibratedProbability(result.Logits[1] - result.Logits[0])
			maxScore = math.Max(maxScore, math.Abs(score-r.Probability))
			if math.Abs(score-r.Probability) > 1e-5 || (score >= Threshold) != r.Unsafe {
				t.Fatalf("score=%g want=%g", score, r.Probability)
			}
			after, _ := json.Marshal(r.Input)
			if !bytes.Equal(before, after) {
				t.Fatal("mutated input")
			}
		})
	}
	if path == "testdata/scoped_golden.json" {
		// A long fixture rejected by the eligibility gate does not exercise
		// packing. Keep admitted reference cases for each cropping branch.
		for _, i := range []int{0, 1, 3} {
			if !cropCoverage[i] {
				t.Errorf("no eligible reference case exercises cropping for field %d", i)
			}
		}
	}
	t.Logf("cases=%d max_logit_error=%g max_score_error=%g", len(rows), maxLogit, maxScore)
}
