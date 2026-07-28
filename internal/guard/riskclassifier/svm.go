package riskclassifier

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"unicode"
)

const (
	// VerdictRisky and VerdictNotRisky are the serving-contract labels.
	VerdictRisky    = "risky"
	VerdictNotRisky = "not_risky"

	portableSchema = "kontext-svm-portable/1"
)

//go:embed model/svm.json.gz
var embeddedModel []byte

// SVMVerdict is the SVM half of a classifier record: the shipped
// char n-gram + LinearSVM model's signed margin and label. Threshold is
// recorded alongside so the dataset stays self-describing when the serving
// operating point is retuned — the raw score makes any verdict re-derivable.
type SVMVerdict struct {
	Verdict      string  `json:"verdict"`
	Score        float64 `json:"score"`
	Threshold    float64 `json:"threshold"`
	ModelVersion string  `json:"model_version"`
}

// SVM scores normalized commands with the exported authz-bench pipeline
// (char_wb 3-5 TF-IDF + LinearSVC), reimplemented natively. Parity with the
// Python reference is enforced by TestSVMGoldenParity.
type SVM struct {
	modelVersion string
	threshold    float64
	ngramMin     int
	ngramMax     int
	intercept    float64
	vocabulary   map[string]int32
	idf          []float64
	coef         []float64
}

type portableModel struct {
	Schema       string    `json:"schema"`
	ModelVersion string    `json:"model_version"`
	Threshold    float64   `json:"threshold"`
	NgramMin     int       `json:"ngram_min"`
	NgramMax     int       `json:"ngram_max"`
	Intercept    float64   `json:"intercept"`
	Ngrams       []string  `json:"ngrams"`
	IDF          []float64 `json:"idf"`
	Coef         []float64 `json:"coef"`
}

var (
	loadOnce     sync.Once
	loadedSVM    *SVM
	loadedSVMErr error
)

// LoadSVM returns the process-wide SVM built from the embedded artifact.
func LoadSVM() (*SVM, error) {
	loadOnce.Do(func() {
		loadedSVM, loadedSVMErr = newSVM(embeddedModel)
	})
	return loadedSVM, loadedSVMErr
}

func newSVM(gzipped []byte) (*SVM, error) {
	reader, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		return nil, fmt.Errorf("open svm artifact: %w", err)
	}
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read svm artifact: %w", err)
	}
	var model portableModel
	if err := json.Unmarshal(raw, &model); err != nil {
		return nil, fmt.Errorf("decode svm artifact: %w", err)
	}
	if model.Schema != portableSchema {
		return nil, fmt.Errorf("svm artifact schema %q, want %q", model.Schema, portableSchema)
	}
	if model.NgramMin <= 0 || model.NgramMax < model.NgramMin {
		return nil, fmt.Errorf("svm artifact ngram range %d-%d is invalid", model.NgramMin, model.NgramMax)
	}
	size := len(model.Ngrams)
	if size == 0 || len(model.IDF) != size || len(model.Coef) != size {
		return nil, fmt.Errorf("svm artifact arrays disagree: %d ngrams, %d idf, %d coef", size, len(model.IDF), len(model.Coef))
	}
	// The threshold is a serving decision carried by the artifact, so retuning
	// it is a re-export rather than a code change. Guard against a nonsense
	// value silently disabling one side of the classifier.
	if model.Threshold < -5 || model.Threshold > 5 {
		return nil, fmt.Errorf("svm artifact threshold %v is out of range", model.Threshold)
	}
	vocabulary := make(map[string]int32, size)
	for i, ngram := range model.Ngrams {
		vocabulary[ngram] = int32(i)
	}
	return &SVM{
		modelVersion: model.ModelVersion,
		threshold:    model.Threshold,
		ngramMin:     model.NgramMin,
		ngramMax:     model.NgramMax,
		intercept:    model.Intercept,
		vocabulary:   vocabulary,
		idf:          model.IDF,
		coef:         model.Coef,
	}, nil
}

// ModelVersion reports the exported model card version stamped on records.
func (s *SVM) ModelVersion() string {
	return s.modelVersion
}

// Threshold reports the serving decision boundary from the artifact.
func (s *SVM) Threshold() float64 {
	return s.threshold
}

// Classify normalizes the raw command and scores it. The returned score is the
// LinearSVC signed margin, rounded like the reference predictor's output; the
// verdict applies the artifact's serving threshold.
func (s *SVM) Classify(command string) SVMVerdict {
	score := s.decisionFunction(NormalizeCommand(command))
	return SVMVerdict{
		Verdict:      verdictForScore(score, s.threshold),
		Score:        math.Round(score*10000) / 10000,
		Threshold:    s.threshold,
		ModelVersion: s.modelVersion,
	}
}

func verdictForScore(score, threshold float64) string {
	if score >= threshold {
		return VerdictRisky
	}
	return VerdictNotRisky
}

func (s *SVM) decisionFunction(normalized string) float64 {
	counts := make(map[int32]int)
	for _, word := range splitPythonWhitespace(pythonLower(normalized)) {
		s.countWordNgrams(word, counts)
	}
	// TfidfVectorizer.transform: term counts scaled by idf, then the row is
	// L2-normalized; LinearSVC decision is the dot with coef plus intercept.
	norm := 0.0
	dot := 0.0
	for index, count := range counts {
		value := float64(count) * s.idf[index]
		norm += value * value
		dot += value * s.coef[index]
	}
	if norm == 0 {
		return s.intercept
	}
	return dot/math.Sqrt(norm) + s.intercept
}

// countWordNgrams mirrors sklearn's _char_wb_ngrams for one word: the word is
// padded with single spaces, then for each n the window slides across the
// padded word; a word shorter than the current n is counted once as-is and
// larger sizes are skipped.
func (s *SVM) countWordNgrams(word string, counts map[int32]int) {
	padded := make([]rune, 0, len(word)+2)
	padded = append(padded, ' ')
	padded = append(padded, []rune(word)...)
	padded = append(padded, ' ')
	length := len(padded)
	for n := s.ngramMin; n <= s.ngramMax; n++ {
		if length <= n {
			s.count(string(padded), counts)
			break
		}
		for offset := 0; offset+n <= length; offset++ {
			s.count(string(padded[offset:offset+n]), counts)
		}
	}
}

func (s *SVM) count(ngram string, counts map[int32]int) {
	if index, ok := s.vocabulary[ngram]; ok {
		counts[index]++
	}
}

// pythonLower mirrors str.lower(): Go's strings.ToLower applies simple case
// mapping, but Python applies the full mapping, where U+0130 (İ) lowers to
// "i" plus a combining dot above.
func pythonLower(s string) string {
	if strings.ContainsRune(s, 'İ') {
		s = strings.ReplaceAll(s, "İ", "i̇")
	}
	return strings.ToLower(s)
}

// splitPythonWhitespace mirrors str.split() with no arguments, whose
// whitespace set (like Python's regex \s) includes the 0x1c-0x1f separators
// that Go's unicode.IsSpace excludes.
func splitPythonWhitespace(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
	})
}
