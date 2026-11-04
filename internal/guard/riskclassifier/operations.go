package riskclassifier

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:embed model/aws_operations.json.gz
var embeddedOperations []byte

// OperationVerdict is local shadow data. Score is a signed margin, not a
// probability or a severity. A nil score means no assessment was possible.
// CombinedVerdict describes a hypothetical OR; it does not replace SVM.Verdict.
// No input text, argument values or parser error messages are retained here.
type OperationVerdict struct {
	ModelVersion     string   `json:"model_version"`
	ExtractorVersion string   `json:"extractor_version"`
	Head             string   `json:"head"`
	Status           string   `json:"status"`
	Score            *float64 `json:"score,omitempty"`
	Threshold        float64  `json:"threshold"`
	Verdict          string   `json:"verdict,omitempty"`
	OperationCount   int      `json:"operation_count"`
	Shadow           bool     `json:"shadow"`
	CombinedVerdict  string   `json:"combined_verdict,omitempty"`
}

type operationHead struct {
	Unit         string    `json:"unit"`
	FeatureNames []string  `json:"feature_names"`
	Weights      []float64 `json:"weights"`
	Intercept    float64   `json:"intercept"`
	Threshold    float64   `json:"threshold"`
	indices      map[string]int
}

// OperationModel is immutable after loading and safe for concurrent scoring.
type OperationModel struct {
	artifact operationArtifact
}

type operationArtifact struct {
	Schema           string                                  `json:"schema"`
	ModelVersion     string                                  `json:"model_version"`
	ExtractorVersion string                                  `json:"extractor_version"`
	Heads            map[string]*operationHead               `json:"heads"`
	ArgumentTypes    map[string]map[string]map[string]string `json:"argument_types"`
}

var operationOnce sync.Once
var operationModel *OperationModel
var operationLoadError error

// LoadOperationModel loads the frozen learned weights and compact syntax-only
// AWS argument table. It does not load an SDK, interpreter or Python runtime.
func LoadOperationModel() (*OperationModel, error) {
	operationOnce.Do(func() {
		operationModel, operationLoadError = loadOperationModel(embeddedOperations)
	})
	return operationModel, operationLoadError
}

func loadOperationModel(data []byte) (*OperationModel, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("operation model gzip: %w", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(io.LimitReader(r, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 {
		return nil, fmt.Errorf("operation model read failed or oversized")
	}
	var m operationArtifact
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("operation model JSON: %w", err)
	}
	if m.Schema != "kontext-aws-operations/1" || m.ModelVersion == "" || m.ExtractorVersion != "aws-cli/1" || len(m.ArgumentTypes) == 0 {
		return nil, fmt.Errorf("invalid operation model metadata")
	}
	for _, unit := range []string{"command", "session"} {
		h := m.Heads[unit]
		if h == nil || h.Unit != unit || len(h.Weights) == 0 || len(h.FeatureNames) != len(h.Weights) || !finite(h.Intercept) || !finite(h.Threshold) {
			return nil, fmt.Errorf("invalid operation model head: %s", unit)
		}
		h.indices = make(map[string]int, len(h.Weights))
		for i, name := range h.FeatureNames {
			if _, duplicate := h.indices[name]; name == "" || duplicate || !finite(h.Weights[i]) {
				return nil, fmt.Errorf("invalid operation model feature")
			}
			h.indices[name] = i
		}
	}
	return &OperationModel{artifact: m}, nil
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// Classify parses the full raw input. Multiple operations are scored separately
// with L2-normalized binary features and aggregated by maximum margin, exactly
// as in the frozen reference. Unknown features are excluded from the norm.
func (m *OperationModel) Classify(command string) OperationVerdict {
	unit := "command"
	if strings.Contains(command, "\n") {
		unit = "session"
	}
	h := m.artifact.Heads[unit]
	verdict := OperationVerdict{ModelVersion: m.artifact.ModelVersion, ExtractorVersion: m.artifact.ExtractorVersion,
		Head: unit, Threshold: h.Threshold, Shadow: true}
	ops, status := extractAWSOperations(command, m.artifact.ArgumentTypes)
	verdict.Status, verdict.OperationCount = status, len(ops)
	if len(ops) == 0 {
		return verdict
	}
	score := math.Inf(-1)
	for _, op := range ops {
		features := operationFeatures(op)
		indices := make([]int, 0, len(features))
		for name := range features {
			if i, ok := h.indices[name]; ok {
				indices = append(indices, i)
			}
		}
		sort.Ints(indices)
		sum := 0.0
		for _, i := range indices {
			sum += h.Weights[i]
		}
		margin := h.Intercept
		if len(indices) > 0 {
			margin += sum / math.Sqrt(float64(len(indices)))
		}
		score = math.Max(score, margin)
	}
	verdict.Score = &score
	verdict.Verdict = verdictForScore(score, h.Threshold)
	return verdict
}

var operationWords = regexp.MustCompile(`[a-z]+`)

func operationFeatures(op awsOperation) map[string]struct{} {
	f := map[string]struct{}{}
	put := func(name string) { f[name] = struct{}{} }
	put("effect:aws")
	put("aws-service:" + op.service)
	put("aws-operation:" + op.operation)
	put("aws-api:" + op.service + "/" + op.operation)
	for _, word := range operationWords.FindAllString(op.operation, -1) {
		put("aws-operation-word:" + word)
		put("aws-service-word:" + op.service + "/" + word)
	}
	for _, flag := range op.flags {
		put("aws-flag:" + flag)
		put("aws-api-flag:" + op.service + "/" + op.operation + "/" + flag)
	}
	return f
}
