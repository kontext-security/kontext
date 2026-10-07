package stepsafety

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"io"
	"math"
	"strings"
	"unicode"
)

type sparseVector struct {
	Features map[string][2]float64 `json:"features"`
}
type scoreCalibration struct{ Coefficient, Intercept float64 }

var agreementModel struct {
	Word, Char         sparseVector
	Intercept          float64
	EncoderCalibration scoreCalibration `json:"encoder_calibrator"`
	SparseCalibration  scoreCalibration `json:"sparse_calibrator"`
	EncoderThreshold   float64          `json:"encoder_threshold"`
	SparseThreshold    float64          `json:"sparse_threshold"`
}

func loadAgreementAssets() error {
	f, err := nativeAssets.Open("model/native/agreement.json.gz")
	if err != nil {
		return err
	}
	defer f.Close()
	reader, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, 4918863+1))
	if err != nil {
		return err
	}
	h := sha256.Sum256(data)
	if len(data) != 4918863 || hex.EncodeToString(h[:]) != "7f01698e14f36f72ccad7f519c4e95298f125c75c469ef25b4b0f08052f1dcc8" {
		return errors.New("agreement asset checksum mismatch")
	}
	return json.Unmarshal(data, &agreementModel)
}

func vectorScore(counts map[string]int, vector sparseVector) float64 {
	var norm, dot float64
	for term, count := range counts {
		h := sha256.Sum256([]byte(term))
		feature, ok := vector.Features[hex.EncodeToString(h[:])]
		if !ok {
			continue
		}
		value := (1 + math.Log(float64(count))) * feature[0]
		norm += value * value
		dot += value * feature[1]
	}
	if norm == 0 {
		return 0
	}
	return dot / math.Sqrt(norm)
}

func pythonSpace(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) }

func sparseMargin(text string) float64 {
	// Match sklearn's lowercase Unicode word analyzer and char analyzer.
	// The vocabulary is hashed to avoid shipping plaintext captured tokens.
	text = cases.Lower(language.Und).String(text)
	words := []string{}
	run := []rune{}
	flush := func() {
		if len(run) >= 2 {
			words = append(words, string(run))
		}
		run = run[:0]
	}
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_' {
			run = append(run, r)
		} else {
			flush()
		}
	}
	flush()
	counts := map[string]int{}
	for i, word := range words {
		counts[word]++
		if i > 0 {
			counts[words[i-1]+" "+word]++
		}
	}
	score := agreementModel.Intercept + vectorScore(counts, agreementModel.Word)
	var normalized strings.Builder
	rr := []rune(text)
	for i := 0; i < len(rr); {
		j := i + 1
		if pythonSpace(rr[i]) {
			for j < len(rr) && pythonSpace(rr[j]) {
				j++
			}
		}
		if j-i >= 2 {
			normalized.WriteByte(' ')
		} else {
			normalized.WriteRune(rr[i])
		}
		i = j
	}
	rr = []rune(normalized.String())
	counts = map[string]int{}
	for n := 3; n <= 5; n++ {
		for i := 0; i+n <= len(rr); i++ {
			counts[string(rr[i:i+n])]++
		}
	}
	return score + vectorScore(counts, agreementModel.Char)
}

func applyAgreement(ctx context.Context, input Input, original InferenceResult) (InferenceResult, error) {
	if err := ctx.Err(); err != nil {
		return InferenceResult{}, err
	}
	fields, err := candidateFields(input)
	if err != nil {
		return InferenceResult{}, err
	}
	e, s := agreementModel.EncoderCalibration, agreementModel.SparseCalibration
	et, st := agreementModel.EncoderThreshold, agreementModel.SparseThreshold
	encoder := e.Coefficient*(original.Logits[1]-original.Logits[0]) + e.Intercept - math.Log(et/(1-et))
	sparse := s.Coefficient*sparseMargin(fields[2]) + s.Intercept - math.Log(st/(1-st))
	if err := ctx.Err(); err != nil {
		return InferenceResult{}, err
	}
	original.Logits = [2]float64{0, math.Min(encoder, sparse)}
	return original, nil
}
