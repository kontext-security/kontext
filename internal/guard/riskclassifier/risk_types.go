package riskclassifier

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
)

const (
	RiskTypeAnnotationSchema = "risk_type_annotation/v1"
	RiskTypeStatusEvaluated  = "evaluated"
	RiskTypePrimaryNone      = "none"

	riskTypePortableSchema = "kontext-risk-type-svm-portable/1"
)

// CanonicalRiskTypes is authz-bench PR #1's product-facing taxonomy in model
// column order. The order is part of the portable contract: labels are emitted
// canonically, while PrimaryRiskType is the highest signed margin.
var CanonicalRiskTypes = []string{
	"arbitrary_code_execution",
	"untrusted_payload_execution",
	"shell_escape_or_remote_shell",
	"privilege_or_permission_change",
	"credential_access",
	"sensitive_data_access",
	"persistence_or_startup_change",
	"security_control_or_log_impairment",
	"discovery_or_reconnaissance",
	"collection_or_staging",
	"exfiltration_or_unauthorized_transfer",
	"network_exposure_or_remote_access",
	"destructive_or_mass_modification",
	"availability_or_service_disruption",
	"system_or_account_configuration_change",
}

//go:embed model/risk_types.json.gz
var embeddedRiskTypeModel []byte

// RiskTypeScore is one one-vs-rest LinearSVC signed margin. It is deliberately
// not called confidence or probability.
type RiskTypeScore struct {
	RiskType string  `json:"risk_type"`
	Score    float64 `json:"score"`
}

// RiskTypeProvenance identifies both the exact Python artifact and the
// annotation source used to train it. ModelVersion versions serving semantics;
// SourceArtifactSHA256 pins the joblib weights byte-for-byte.
type RiskTypeProvenance struct {
	ModelVersion            string `json:"model_version"`
	SourceArtifactSHA256    string `json:"source_artifact_sha256"`
	SourceRevision          string `json:"source_revision"`
	SourcePR                string `json:"source_pr"`
	AnnotationSHA256        string `json:"annotation_sha256"`
	AnnotationSchemaVersion string `json:"annotation_schema_version"`
	AnnotationPromptVersion string `json:"annotation_prompt_version"`
}

// RiskTypeVerdict is the advisory second-stage result. Empty RiskTypes with
// PrimaryRiskType "none" is a successful abstention, not an error: the binary
// upstream verdict can itself be a false positive.
type RiskTypeVerdict struct {
	SchemaVersion   string             `json:"schema_version"`
	Status          string             `json:"status"`
	RiskTypes       []string           `json:"risk_types"`
	PrimaryRiskType string             `json:"primary_risk_type"`
	Scores          []RiskTypeScore    `json:"scores"`
	Threshold       float64            `json:"threshold"`
	Abstained       bool               `json:"abstained"`
	Provenance      RiskTypeProvenance `json:"provenance"`
}

// Validate pins the derived wire shape independently of DecisionFactV1.
func (v RiskTypeVerdict) Validate() error {
	if v.SchemaVersion != RiskTypeAnnotationSchema || v.Status != RiskTypeStatusEvaluated {
		return fmt.Errorf("invalid risk-type annotation schema or status")
	}
	if !sameStrings(scoreLabels(v.Scores), CanonicalRiskTypes) {
		return fmt.Errorf("risk-type scores do not match the canonical taxonomy")
	}
	for _, score := range v.Scores {
		if math.IsNaN(score.Score) || math.IsInf(score.Score, 0) {
			return fmt.Errorf("risk-type score for %s must be finite", score.RiskType)
		}
	}
	if math.IsNaN(v.Threshold) || math.IsInf(v.Threshold, 0) {
		return fmt.Errorf("risk-type threshold must be finite")
	}
	expectedRiskTypes := make([]string, 0, len(v.Scores))
	expectedPrimary := RiskTypePrimaryNone
	primaryScore := math.Inf(-1)
	for _, score := range v.Scores {
		if score.Score < v.Threshold {
			continue
		}
		expectedRiskTypes = append(expectedRiskTypes, score.RiskType)
		if score.Score > primaryScore {
			expectedPrimary = score.RiskType
			primaryScore = score.Score
		}
	}
	if !sameStrings(v.RiskTypes, expectedRiskTypes) {
		return fmt.Errorf("risk types do not match thresholded score margins")
	}
	if len(v.RiskTypes) == 0 {
		if !v.Abstained || v.PrimaryRiskType != RiskTypePrimaryNone {
			return fmt.Errorf("empty risk types require an abstention with primary none")
		}
	} else {
		if v.Abstained {
			return fmt.Errorf("non-empty risk types cannot be an abstention")
		}
		if v.PrimaryRiskType != expectedPrimary {
			return fmt.Errorf("primary risk type is not the highest positive margin")
		}
	}
	provenance := v.Provenance
	if provenance.ModelVersion == "" || provenance.SourceArtifactSHA256 == "" || provenance.SourceRevision == "" ||
		provenance.SourcePR == "" || provenance.AnnotationSHA256 == "" || provenance.AnnotationSchemaVersion == "" ||
		provenance.AnnotationPromptVersion == "" {
		return fmt.Errorf("risk-type annotation has incomplete provenance")
	}
	return nil
}

func scoreLabels(scores []RiskTypeScore) []string {
	labels := make([]string, len(scores))
	for index, score := range scores {
		labels[index] = score.RiskType
	}
	return labels
}

// RiskTypeSVM is authz-bench's char_wb TF-IDF plus one LinearSVC per canonical
// risk type, ported directly to Go. Unlike the binary SVM it consumes the raw
// command: risk_types/train.py applies no benchmark normalizer before
// TfidfVectorizer's own lowercase + char_wb preprocessing.
type RiskTypeSVM struct {
	threshold    float64
	ngramMin     int
	ngramMax     int
	vocabulary   map[string]int32
	idf          []float64
	intercepts   []float64
	coefficients [][]float64
	labels       []string
	provenance   RiskTypeProvenance
}

type riskTypePortableModel struct {
	Schema           string                  `json:"schema"`
	AnnotationSchema string                  `json:"annotation_schema"`
	ModelVersion     string                  `json:"model_version"`
	Provenance       riskTypeModelProvenance `json:"provenance"`
	Threshold        float64                 `json:"threshold"`
	Vectorizer       riskTypeVectorizer      `json:"vectorizer"`
	Labels           []string                `json:"labels"`
	Ngrams           []string                `json:"ngrams"`
	IDF              []float64               `json:"idf"`
	Intercepts       []float64               `json:"intercepts"`
	Coefficients     [][]float64             `json:"coefficients"`
}

type riskTypeModelProvenance struct {
	SourcePR                string `json:"source_pr"`
	SourceRevision          string `json:"source_revision"`
	SourceArtifactSHA256    string `json:"source_artifact_sha256"`
	AnnotationSHA256        string `json:"annotation_sha256"`
	AnnotationSchemaVersion string `json:"annotation_schema_version"`
	AnnotationPromptVersion string `json:"annotation_prompt_version"`
}

type riskTypeVectorizer struct {
	Analyzer    string `json:"analyzer"`
	Lowercase   bool   `json:"lowercase"`
	NgramMin    int    `json:"ngram_min"`
	NgramMax    int    `json:"ngram_max"`
	Norm        string `json:"norm"`
	UseIDF      bool   `json:"use_idf"`
	SmoothIDF   bool   `json:"smooth_idf"`
	SublinearTF bool   `json:"sublinear_tf"`
	MinDF       int    `json:"min_df"`
	MaxFeatures int    `json:"max_features"`
}

var (
	riskTypeLoadOnce sync.Once
	loadedRiskTypes  *RiskTypeSVM
	riskTypeLoadErr  error
)

// LoadRiskTypeSVM returns the process-wide native model. Callers must treat an
// error as advisory degradation; the binary verdict and tool call continue.
func LoadRiskTypeSVM() (*RiskTypeSVM, error) {
	riskTypeLoadOnce.Do(func() {
		loadedRiskTypes, riskTypeLoadErr = newRiskTypeSVM(embeddedRiskTypeModel)
	})
	return loadedRiskTypes, riskTypeLoadErr
}

func newRiskTypeSVM(gzipped []byte) (*RiskTypeSVM, error) {
	reader, err := gzip.NewReader(bytes.NewReader(gzipped))
	if err != nil {
		return nil, fmt.Errorf("open risk-type svm artifact: %w", err)
	}
	defer reader.Close()
	raw, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read risk-type svm artifact: %w", err)
	}
	var model riskTypePortableModel
	if err := json.Unmarshal(raw, &model); err != nil {
		return nil, fmt.Errorf("decode risk-type svm artifact: %w", err)
	}
	if err := validateRiskTypePortableModel(model); err != nil {
		return nil, err
	}
	vocabulary := make(map[string]int32, len(model.Ngrams))
	for index, ngram := range model.Ngrams {
		vocabulary[ngram] = int32(index)
	}
	return &RiskTypeSVM{
		threshold:    model.Threshold,
		ngramMin:     model.Vectorizer.NgramMin,
		ngramMax:     model.Vectorizer.NgramMax,
		vocabulary:   vocabulary,
		idf:          model.IDF,
		intercepts:   model.Intercepts,
		coefficients: model.Coefficients,
		labels:       append([]string{}, model.Labels...),
		provenance: RiskTypeProvenance{
			ModelVersion:            model.ModelVersion,
			SourceArtifactSHA256:    model.Provenance.SourceArtifactSHA256,
			SourceRevision:          model.Provenance.SourceRevision,
			SourcePR:                model.Provenance.SourcePR,
			AnnotationSHA256:        model.Provenance.AnnotationSHA256,
			AnnotationSchemaVersion: model.Provenance.AnnotationSchemaVersion,
			AnnotationPromptVersion: model.Provenance.AnnotationPromptVersion,
		},
	}, nil
}

func validateRiskTypePortableModel(model riskTypePortableModel) error {
	if model.Schema != riskTypePortableSchema {
		return fmt.Errorf("risk-type svm artifact schema %q, want %q", model.Schema, riskTypePortableSchema)
	}
	if model.AnnotationSchema != RiskTypeAnnotationSchema {
		return fmt.Errorf("risk-type annotation schema %q, want %q", model.AnnotationSchema, RiskTypeAnnotationSchema)
	}
	provenance := model.Provenance
	if model.ModelVersion == "" || provenance.SourcePR == "" || provenance.SourceRevision == "" ||
		provenance.SourceArtifactSHA256 == "" || provenance.AnnotationSHA256 == "" ||
		provenance.AnnotationSchemaVersion == "" || provenance.AnnotationPromptVersion == "" {
		return fmt.Errorf("risk-type svm artifact has incomplete provenance")
	}
	vectorizer := model.Vectorizer
	if vectorizer.Analyzer != "char_wb" || !vectorizer.Lowercase || vectorizer.NgramMin != 3 || vectorizer.NgramMax != 5 ||
		vectorizer.Norm != "l2" || !vectorizer.UseIDF || !vectorizer.SmoothIDF || vectorizer.SublinearTF ||
		vectorizer.MinDF != 2 || vectorizer.MaxFeatures != 50000 {
		return fmt.Errorf("risk-type svm artifact vectorizer is not the supported char_wb contract")
	}
	if !sameStrings(model.Labels, CanonicalRiskTypes) {
		return fmt.Errorf("risk-type svm labels do not match the canonical taxonomy")
	}
	featureCount := len(model.Ngrams)
	labelCount := len(model.Labels)
	if featureCount == 0 || len(model.IDF) != featureCount || len(model.Intercepts) != labelCount || len(model.Coefficients) != labelCount {
		return fmt.Errorf("risk-type svm artifact arrays disagree")
	}
	seen := make(map[string]struct{}, featureCount)
	for _, ngram := range model.Ngrams {
		if ngram == "" {
			return fmt.Errorf("risk-type svm vocabulary contains an empty feature")
		}
		if _, exists := seen[ngram]; exists {
			return fmt.Errorf("risk-type svm vocabulary contains duplicate feature %q", ngram)
		}
		seen[ngram] = struct{}{}
	}
	for index, coefficient := range model.Coefficients {
		if len(coefficient) != featureCount {
			return fmt.Errorf("risk-type svm coefficients[%d] has %d features, want %d", index, len(coefficient), featureCount)
		}
	}
	if math.IsNaN(model.Threshold) || math.IsInf(model.Threshold, 0) {
		return fmt.Errorf("risk-type svm threshold must be finite")
	}
	return nil
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// Classify returns all heads at or above the artifact's exact threshold and
// the highest-margin positive head as primary. No positive heads is a valid
// abstention with primary "none".
func (s *RiskTypeSVM) Classify(command string) RiskTypeVerdict {
	scores := s.decisionFunctions(command)
	riskTypes := make([]string, 0, len(scores))
	scoreRows := make([]RiskTypeScore, len(scores))
	primary := RiskTypePrimaryNone
	primaryScore := math.Inf(-1)
	for index, score := range scores {
		label := s.labels[index]
		scoreRows[index] = RiskTypeScore{RiskType: label, Score: score}
		if score < s.threshold {
			continue
		}
		riskTypes = append(riskTypes, label)
		if score > primaryScore {
			primary, primaryScore = label, score
		}
	}
	return RiskTypeVerdict{
		SchemaVersion:   RiskTypeAnnotationSchema,
		Status:          RiskTypeStatusEvaluated,
		RiskTypes:       riskTypes,
		PrimaryRiskType: primary,
		Scores:          scoreRows,
		Threshold:       s.threshold,
		Abstained:       len(riskTypes) == 0,
		Provenance:      s.provenance,
	}
}

func (s *RiskTypeSVM) decisionFunctions(command string) []float64 {
	counts := make(map[int32]int)
	for _, word := range splitPythonWhitespace(pythonLower(command)) {
		s.countWordNgrams(word, counts)
	}
	indices := make([]int, 0, len(counts))
	for index := range counts {
		indices = append(indices, int(index))
	}
	// scipy's CSR rows have sorted feature indices. Sorting also makes the Go
	// sum deterministic across processes instead of depending on map order.
	sort.Ints(indices)
	values := make([]float64, len(indices))
	norm := 0.0
	for position, index := range indices {
		value := float64(counts[int32(index)]) * s.idf[index]
		values[position] = value
		norm += value * value
	}
	if norm != 0 {
		scale := 1 / math.Sqrt(norm)
		for index := range values {
			values[index] *= scale
		}
	}
	scores := append([]float64{}, s.intercepts...)
	for label := range scores {
		for position, feature := range indices {
			scores[label] += values[position] * s.coefficients[label][feature]
		}
	}
	return scores
}

func (s *RiskTypeSVM) countWordNgrams(word string, counts map[int32]int) {
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

func (s *RiskTypeSVM) count(ngram string, counts map[int32]int) {
	if index, ok := s.vocabulary[ngram]; ok {
		counts[index]++
	}
}

// IsShellCommandTool is deliberately an allowlist, not a substring match.
// Payloads from apply_patch and arbitrary tools can contain a "command" key or
// shell-looking text but were never executed by a shell.
func IsShellCommandTool(toolName string) bool {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "bash", "shell", "shell_command", "exec_command", "functions.exec_command":
		return true
	default:
		return false
	}
}
