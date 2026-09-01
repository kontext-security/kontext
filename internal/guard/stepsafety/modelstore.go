package stepsafety

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type artifactSpec struct {
	Name   string `json:"name"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

var requiredArtifacts = []artifactSpec{
	{Name: "config.json", Size: 924, SHA256: "41f89ae28c4f0549b92537d0ef5918ef9e1af25e9898af6456e3551bf0a93852"},
	{Name: "model.safetensors", Size: 283201512, SHA256: "075d68f8bb4c1b4b98e2d2b2c0d5b013056b202172b080b34e7364b698844c86"},
	{Name: "tokenizer.json", Size: 8340654, SHA256: "d6c20af053b5d86d986a9f70898c1fceccb9d93e7ce6f63dabc899a12a53b031"},
	{Name: "tokenizer_config.json", Size: 601, SHA256: "141468772d3b095cc30275fd9c05dff92a78619c341487da9f5549a3564ea6cb"},
}

const (
	sourceRevision       = "9c63e6191598b0ba72947a4394ac8297c41053d1"
	sourceArtifactPath   = "artifacts/models/history_serialization/deberta_v3_xsmall"
	sourceResultsPath    = "results/history_serialization_ablation.json"
	sourceResultsSHA256  = "09efd898c02dedb1ad8f83dd5b90888e84cbcf8919c51450c9289176c42db41a"
	sourceFindingsPath   = "docs/HISTORY_SERIALIZATION_ABLATION_FINDINGS.md"
	sourceFindingsSHA256 = "f4231362a77e8d622ace51c4d8ac323fc801cca6ebc6771d5295b55df2bef08f"
	sourceSerializerPath = "src/toolsafe_lab/history_serialization.py"
	sourceSerializerSHA  = "4b14a72a6825555d56c4be0549039428b78332940d3cdd25516ef278888642e2"
	sourcePackingPath    = "src/toolsafe_lab/standalone_encoder.py"
	sourcePackingSHA     = "ca8db9401025c8489a142d9447140a857fd77df84e5246fde92c995ccbe173ff"
	sourceProtocolPath   = "docs/HISTORY_SERIALIZATION_ABLATION_PROTOCOL.md"
	sourceProtocolSHA    = "6e44e1175be44573e6feef1130ef9f4faeaf8457025c79d5100212c568099089"
)

const microsoftMITLicense = `MIT License

Copyright (c) Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE
`

type Provenance struct {
	SchemaVersion        int                            `json:"schema_version"`
	ModelVersion         string                         `json:"model_version"`
	SourceProject        string                         `json:"source_project"`
	SourceRevision       string                         `json:"source_revision"`
	SourceArtifactPath   string                         `json:"source_artifact_path,omitempty"`
	SourceResultsPath    string                         `json:"source_results_path,omitempty"`
	SourceResultsSHA256  string                         `json:"source_results_sha256,omitempty"`
	SourceFindingsPath   string                         `json:"source_findings_path,omitempty"`
	SourceFindingsSHA256 string                         `json:"source_findings_sha256,omitempty"`
	SourceSerializerPath string                         `json:"source_serializer_path,omitempty"`
	SourceSerializerSHA  string                         `json:"source_serializer_sha256,omitempty"`
	SourcePackingPath    string                         `json:"source_packing_path,omitempty"`
	SourcePackingSHA     string                         `json:"source_packing_sha256,omitempty"`
	SourceProtocolPath   string                         `json:"source_protocol_path,omitempty"`
	SourceProtocolSHA    string                         `json:"source_protocol_sha256,omitempty"`
	BaseModel            string                         `json:"base_model"`
	BaseModelRevision    string                         `json:"base_model_revision"`
	BaseModelLicense     string                         `json:"base_model_license"`
	InputMode            string                         `json:"input_mode"`
	ThoughtIncluded      bool                           `json:"thought_included"`
	HistorySerialization historySerializationProvenance `json:"history_serialization"`
	Evaluation           evaluationProvenance           `json:"evaluation"`
	MaxLength            int                            `json:"max_length"`
	FieldMarkers         map[string]string              `json:"field_markers"`
	FieldBudgets         map[string]int                 `json:"field_budgets"`
	CalibrationScale     float64                        `json:"calibration_scale"`
	CalibrationBias      float64                        `json:"calibration_bias"`
	InitialThreshold     float64                        `json:"initial_threshold"`
	ImportedAt           time.Time                      `json:"imported_at"`
	Artifacts            []artifactSpec                 `json:"artifacts"`
}

type historySerializationProvenance struct {
	EventFields  []string `json:"event_fields"`
	EmptyHistory string   `json:"empty_history"`
	Observations string   `json:"observations"`
	JSONEncoding string   `json:"json_encoding"`
}

type evaluationProvenance struct {
	Threshold         float64 `json:"threshold"`
	Accuracy          float64 `json:"accuracy"`
	Precision         float64 `json:"precision"`
	Recall            float64 `json:"recall"`
	F1                float64 `json:"f1"`
	MCC               float64 `json:"mcc"`
	WorstSourceRecall float64 `json:"worst_source_recall"`
}

func DefaultModelDir(dbPath string) string {
	root := filepath.Join(filepath.Dir(dbPath), "judge-models")
	return filepath.Join(root, "toolsafe", ModelVersion)
}

func ValidateModelDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return backendError(ErrorUnavailable, errors.New("step-safety model directory is empty"))
	}
	for _, artifact := range requiredArtifacts {
		path := filepath.Join(dir, artifact.Name)
		info, err := os.Stat(path)
		if err != nil {
			return backendError(ErrorUnavailable, fmt.Errorf("model artifact %s is unavailable", artifact.Name))
		}
		if !info.Mode().IsRegular() || info.Size() != artifact.Size {
			return backendError(ErrorUnavailable, fmt.Errorf("model artifact %s has unexpected size", artifact.Name))
		}
		digest, err := fileSHA256(path)
		if err != nil || digest != artifact.SHA256 {
			return backendError(ErrorUnavailable, fmt.Errorf("model artifact %s failed checksum verification", artifact.Name))
		}
	}
	return nil
}

// InstallModel copies only inference artifacts into Kontext's existing
// database-adjacent model cache. It never imports the 849 MB training resume
// checkpoint and leaves no reference to the source tree.
func InstallModel(sourceDir, destinationDir string) (string, error) {
	if err := ValidateModelDir(sourceDir); err != nil {
		return "", err
	}
	if err := ValidateModelDir(destinationDir); err == nil {
		return destinationDir, nil
	} else if _, statErr := os.Stat(destinationDir); statErr == nil {
		return "", fmt.Errorf("step-safety destination already exists but is invalid: %s", destinationDir)
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	parent := filepath.Dir(destinationDir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	temporary, err := os.MkdirTemp(parent, ".step-safety-install-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temporary)

	for _, artifact := range requiredArtifacts {
		if err := copyArtifact(filepath.Join(sourceDir, artifact.Name), filepath.Join(temporary, artifact.Name)); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(temporary, "LICENSE"), []byte(microsoftMITLicense), 0o600); err != nil {
		return "", err
	}
	provenance := Provenance{
		SchemaVersion:        2,
		ModelVersion:         ModelVersion,
		SourceProject:        "kontext-security/toolsafe-lab",
		SourceRevision:       sourceRevision,
		SourceArtifactPath:   sourceArtifactPath,
		SourceResultsPath:    sourceResultsPath,
		SourceResultsSHA256:  sourceResultsSHA256,
		SourceFindingsPath:   sourceFindingsPath,
		SourceFindingsSHA256: sourceFindingsSHA256,
		SourceSerializerPath: sourceSerializerPath,
		SourceSerializerSHA:  sourceSerializerSHA,
		SourcePackingPath:    sourcePackingPath,
		SourcePackingSHA:     sourcePackingSHA,
		SourceProtocolPath:   sourceProtocolPath,
		SourceProtocolSHA:    sourceProtocolSHA,
		BaseModel:            "microsoft/deberta-v3-xsmall",
		BaseModelRevision:    "4b419818330868dff6a60ad3e6b1c730f8b8c0c6",
		BaseModelLicense:     "MIT",
		InputMode:            "execution_context + canonical structured history (agent Thought excluded)",
		ThoughtIncluded:      false,
		HistorySerialization: historySerializationProvenance{
			EventFields:  []string{"tool", "arguments", "observation"},
			EmptyHistory: "[]",
			Observations: "strings",
			JSONEncoding: "UTF-8, sorted keys, compact separators",
		},
		Evaluation: evaluationProvenance{
			Threshold:         Threshold,
			Accuracy:          0.9118629908103593,
			Precision:         0.9266195885784464,
			Recall:            0.8845252051582649,
			F1:                0.9050832208726945,
			MCC:               0.8236797425872459,
			WorstSourceRecall: 0.5085227272727273,
		},
		MaxLength: 512,
		FieldMarkers: map[string]string{
			"request": "[USER_REQUEST]",
			"history": "[INTERACTION_HISTORY]",
			"action":  "[CURRENT_ACTION]",
			"schema":  "[TOOL_DESCRIPTIONS]",
		},
		FieldBudgets: map[string]int{
			"request": 96,
			"history": 144,
			"action":  128,
			"schema":  128,
		},
		CalibrationScale: calibrationScale,
		CalibrationBias:  calibrationBias,
		InitialThreshold: Threshold,
		ImportedAt:       time.Now().UTC(),
		Artifacts:        append([]artifactSpec(nil), requiredArtifacts...),
	}
	encoded, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(temporary, "PROVENANCE.json"), append(encoded, '\n'), 0o600); err != nil {
		return "", err
	}
	if err := ValidateModelDir(temporary); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, destinationDir); err != nil {
		return "", err
	}
	return destinationDir, nil
}

func RequiredArtifacts() []string {
	names := make([]string, 0, len(requiredArtifacts))
	for _, artifact := range requiredArtifacts {
		names = append(names, artifact.Name)
	}
	sort.Strings(names)
	return names
}

func copyArtifact(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	return errors.Join(copyErr, closeErr)
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
