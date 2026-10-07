package stepsafety

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestV3NativeProvenanceAndAssets(t *testing.T) {
	data, err := os.ReadFile("model/native/PROVENANCE.json")
	if err != nil {
		t.Fatal(err)
	}
	var provenance struct {
		Model    string `json:"model_version"`
		Weights  string `json:"source_weights_sha256"`
		Advisory bool   `json:"advisory_only"`
		Score    string `json:"score_semantics"`
	}
	if err := json.Unmarshal(data, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.Model != ModelVersion || provenance.Weights != nativeWeightsSHA256 || !provenance.Advisory || provenance.Score == "" {
		t.Fatalf("serving provenance mismatch: %+v", provenance)
	}
	data, err = os.ReadFile("model/native/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Files []artifactSpec `json:"files"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Files) != 8 {
		t.Fatalf("expected weights, tokenizer and both learned filters: %d", len(manifest.Files))
	}
	for _, file := range manifest.Files {
		data, err := nativeAssets.ReadFile("model/native/" + file.Name)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(data)
		if int64(len(data)) != file.Size || hex.EncodeToString(digest[:]) != file.SHA256 {
			t.Fatalf("asset mismatch: %s", file.Name)
		}
	}
}
