package stepsafety

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"slices"
	"testing"
)

func TestCandidateMatchesPython(t *testing.T) {
	m, tok := nativeTestModel(t)
	data, err := os.ReadFile("testdata/candidate_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Candidate  string
		Weights    string `json:"weights_sha256"`
		Threshold  float64
		Calibrator struct{ Coefficient, Intercept float64 }
		Cases      []struct {
			Name        string
			Input       *Input
			Fields      [4]string
			IDs         []int64 `json:"input_ids"`
			Mask        []int64 `json:"attention_mask"`
			Logits      [2]float64
			Probability float64
			Unsafe      bool
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Candidate != ModelVersion || fixture.Weights != nativeWeightsSHA256 || fixture.Threshold != Threshold || fixture.Calibrator.Coefficient != calibrationScale || fixture.Calibrator.Intercept != calibrationBias {
		t.Fatal("candidate provenance differs")
	}
	var maxLogit, maxProbability float64
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			p := packedInput{IDs: c.IDs, Mask: c.Mask}
			if c.Input != nil {
				before, _ := json.Marshal(c.Input)
				fields, err := candidateFields(*c.Input)
				if err != nil || fields != c.Fields {
					t.Fatalf("normalized fields differ: %v\ngot %q\nwant %q", err, fields, c.Fields)
				}
				p, err = packInput(context.Background(), tok, *c.Input)
				if err != nil || !slices.Equal(p.IDs, c.IDs) || !slices.Equal(p.Mask, c.Mask) {
					t.Fatalf("packed tokens differ: %v", err)
				}
				after, _ := json.Marshal(c.Input)
				if !bytes.Equal(before, after) {
					t.Fatal("normalization mutated hook input")
				}
			}
			got, err := m.infer(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			for i, want := range c.Logits {
				delta := math.Abs(got.Logits[i] - want)
				maxLogit = max(maxLogit, delta)
				if delta > 2e-5 {
					t.Fatalf("logits %v != reference %v", got.Logits, c.Logits)
				}
			}
			probability := CalibratedProbability(got.Logits[1] - got.Logits[0])
			maxProbability = max(maxProbability, math.Abs(probability-c.Probability))
			if math.Abs(probability-c.Probability) > 1e-5 || (probability >= Threshold) != c.Unsafe {
				t.Fatalf("score/decision differs: %.9f vs %.9f", probability, c.Probability)
			}
		})
	}
	t.Logf("cases=%d max_logit_error=%g max_probability_error=%g", len(fixture.Cases), maxLogit, maxProbability)
}

func TestEmbeddedTokenizerMatchesHuggingFace(t *testing.T) {
	_, tok := nativeTestModel(t)
	data, err := os.ReadFile("testdata/tokenizer_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			Text string
			IDs  []int64
		}
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	for i, c := range fixture.Cases {
		ids, err := tok.encode(context.Background(), c.Text)
		if err != nil || !slices.Equal(ids, c.IDs) {
			t.Fatalf("tokenizer reference %d differs: %v", i, err)
		}
	}
	t.Logf("matched %d tokenizer vectors", len(fixture.Cases))
}
