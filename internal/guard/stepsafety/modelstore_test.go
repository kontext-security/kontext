package stepsafety

import (
	"encoding/json"
	"os"
	"reflect"
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
	if provenance.SchemaVersion != 2 || provenance.SourceRevision != sourceRevision ||
		provenance.SourceArtifactPath != sourceArtifactPath || provenance.SourceResultsSHA256 != sourceResultsSHA256 ||
		provenance.SourceFindingsSHA256 != sourceFindingsSHA256 ||
		provenance.SourceSerializerPath != sourceSerializerPath || provenance.SourceSerializerSHA != sourceSerializerSHA ||
		provenance.SourcePackingPath != sourcePackingPath || provenance.SourcePackingSHA != sourcePackingSHA ||
		provenance.SourceProtocolPath != sourceProtocolPath || provenance.SourceProtocolSHA != sourceProtocolSHA {
		t.Fatalf("source provenance = %+v", provenance)
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
	if !reflect.DeepEqual(provenance.HistorySerialization.EventFields, []string{"tool", "arguments", "observation"}) ||
		provenance.HistorySerialization.EmptyHistory != "[]" || provenance.HistorySerialization.Observations != "strings" {
		t.Fatalf("history provenance = %+v", provenance.HistorySerialization)
	}
	if provenance.Evaluation.Threshold != Threshold || provenance.Evaluation.WorstSourceRecall != 0.5085227272727273 {
		t.Fatalf("evaluation provenance = %+v", provenance.Evaluation)
	}
	if !reflect.DeepEqual(provenance.Artifacts, requiredArtifacts) {
		t.Fatalf("artifacts = %+v, want %+v", provenance.Artifacts, requiredArtifacts)
	}
}
