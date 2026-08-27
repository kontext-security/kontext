package stepsafety

import (
	"encoding/json"
	"os"
	"testing"
)

func TestTrackedProvenanceMatchesServingContract(t *testing.T) {
	data, err := os.ReadFile("model/PROVENANCE.json")
	if err != nil {
		t.Fatal(err)
	}
	var provenance Provenance
	if err := json.Unmarshal(data, &provenance); err != nil {
		t.Fatal(err)
	}
	if provenance.ModelVersion != ModelVersion || provenance.MaxLength != 512 {
		t.Fatalf("provenance = %+v", provenance)
	}
	if provenance.BaseModelRevision != "4b419818330868dff6a60ad3e6b1c730f8b8c0c6" || provenance.BaseModelLicense != "MIT" {
		t.Fatalf("base model provenance = %+v", provenance)
	}
	if provenance.FieldBudgets["request"] != 96 || provenance.FieldBudgets["history"] != 144 ||
		provenance.FieldBudgets["action"] != 128 || provenance.FieldBudgets["schema"] != 128 {
		t.Fatalf("field budgets = %+v", provenance.FieldBudgets)
	}
	if provenance.CalibrationScale != calibrationScale || provenance.CalibrationBias != calibrationBias || provenance.InitialThreshold != Threshold {
		t.Fatalf("calibration provenance = %+v", provenance)
	}
	if len(provenance.Artifacts) != len(requiredArtifacts) {
		t.Fatalf("artifact count = %d, want %d", len(provenance.Artifacts), len(requiredArtifacts))
	}
}
