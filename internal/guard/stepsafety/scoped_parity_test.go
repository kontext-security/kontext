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
		Name          string
		Input         Input
		Fields        [4]string
		IDs           []int64 `json:"input_ids"`
		Mask          []int64 `json:"attention_mask"`
		Logits        [2]float64
		Probability   float64
		Unsafe        bool
		Error         string
		RequestIntent *float64 `json:"request_intent_probability"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if e = decoder.Decode(&rows); e != nil {
		t.Fatal(e)
	}
	b, e := newNativeBackend(context.Background(), normalizeConfig(Config{}))
	if e != nil {
		t.Fatal(e)
	}
	maxLogit, maxScore := 0., 0.
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
			if !slices.Equal(packed.IDs, r.IDs) || !slices.Equal(packed.Mask, r.Mask) {
				t.Fatalf("Python/Go token mismatch")
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
	t.Logf("cases=%d max_logit_error=%g max_score_error=%g", len(rows), maxLogit, maxScore)
}
