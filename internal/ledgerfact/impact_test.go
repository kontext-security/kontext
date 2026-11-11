package ledgerfact_test

import (
	"encoding/json"
	"math"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/ledgerfact"
)

func TestImpactFactContract(t *testing.T) {
	fixtures, _ := loadFixtures(t)
	var fact ledgerfact.DecisionFact
	if err := json.Unmarshal(fixtures[0].Fact, &fact); err != nil {
		t.Fatal(err)
	}
	fact.Classifier = &ledgerfact.Classifier{SVM: &ledgerfact.ClassifierSVM{Verdict: "safe", Score: -2, ModelVersion: "legacy"}}
	score := 3.529220840949289
	valid := ledgerfact.ClassifierImpact{ModelVersion: "command-risk-process/9-P_process", ExtractorVersion: "kontext-command-risk-features/2", ModelSHA256: strings.Repeat("a", 64), Status: "parsed", Score: &score, Threshold: 1.1957946473415046, Verdict: "flagged"}
	fact.Classifier.Impact = &valid
	if err := fact.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ledgerfact.ClassifierImpact){
		func(v *ledgerfact.ClassifierImpact) { v.Enforced = true },
		func(v *ledgerfact.ClassifierImpact) { v.ModelSHA256 = "bad" },
		func(v *ledgerfact.ClassifierImpact) { v.Score = nil },
		func(v *ledgerfact.ClassifierImpact) { v.Threshold = math.NaN() },
		func(v *ledgerfact.ClassifierImpact) { v.Verdict = "below_threshold" },
		func(v *ledgerfact.ClassifierImpact) { v.Status = "model_unavailable" },
		func(v *ledgerfact.ClassifierImpact) { v.Status = "unknown" },
	} {
		value := valid
		mutate(&value)
		fact.Classifier.Impact = &value
		if fact.Validate() == nil {
			t.Fatalf("invalid annotation accepted: %+v", value)
		}
	}
	for _, status := range []string{"limit_exceeded", "model_unavailable", "inference_error"} {
		value := valid
		value.Status = status
		value.Score = nil
		value.Verdict = "not_assessed"
		fact.Classifier.Impact = &value
		if err := fact.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	fact.Classifier.Impact = nil
	wire, err := json.Marshal(fact)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), `"impact"`) {
		t.Fatal("optional field changes old fact serialization")
	}
}
