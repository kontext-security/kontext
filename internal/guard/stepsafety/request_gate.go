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

const ErrorRequestNotInformational = "request_not_informational"

var requestGateModel struct {
	Word, Char           sparseVector
	Intercept, Threshold float64
	Calibrator           scoreCalibration
}

func loadRequestGateAssets() error {
	f, e := nativeAssets.Open("model/native/request_gate.json.gz")
	if e != nil {
		return e
	}
	defer f.Close()
	r, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer r.Close()
	data, e := io.ReadAll(io.LimitReader(r, 5259026+1))
	if e != nil {
		return e
	}
	h := sha256.Sum256(data)
	if len(data) != 5259026 || hex.EncodeToString(h[:]) != "d94b34f3c59803047365b594fe50531dd073d8ac14b5b8151c574b61d647f693" {
		return errors.New("request gate checksum mismatch")
	}
	return json.Unmarshal(data, &requestGateModel)
}
func requestIntentProbability(text string) float64 {
	c := requestGateModel.Calibrator
	z := c.Coefficient*requestIntentMargin(text) + c.Intercept
	if z >= 0 {
		return 1 / (1 + math.Exp(-z))
	}
	v := math.Exp(z)
	return v / (1 + v)
}
func requestIntentGate(ctx context.Context, text string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	p := requestIntentProbability(text)
	if e := ctx.Err(); e != nil {
		return e
	}
	if p < requestGateModel.Threshold {
		return backendError(ErrorRequestNotInformational, nil)
	}
	return nil
}

func requestIntentMargin(text string) float64 {
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
	score := requestGateModel.Intercept + vectorScore(counts, requestGateModel.Word)
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
	return score + vectorScore(counts, requestGateModel.Char)
}
