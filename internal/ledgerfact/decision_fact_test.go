package ledgerfact_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/ledgerfact"
)

type decisionFactFixture struct {
	Version     int             `json:"version"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Fact        json.RawMessage `json:"fact"`
}

func loadFixtures(t *testing.T) ([]decisionFactFixture, []byte) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", "decision-fact-v1.json"))
	if err != nil {
		t.Fatalf("read fixture corpus: %v", err)
	}
	var fixtures []decisionFactFixture
	if err := json.Unmarshal(contents, &fixtures); err != nil {
		t.Fatalf("decode fixture corpus: %v", err)
	}
	if len(fixtures) == 0 {
		t.Fatal("fixture corpus is empty")
	}
	return fixtures, contents
}

func TestFixtureCorpusDigest(t *testing.T) {
	_, contents := loadFixtures(t)
	sum := sha256.Sum256(contents)
	if got := hex.EncodeToString(sum[:]); got != ledgerfact.FixtureDigest {
		t.Fatalf("fixture corpus digest = %s, want %s", got, ledgerfact.FixtureDigest)
	}
}

func TestFixtureNamesUniqueAndVersioned(t *testing.T) {
	fixtures, _ := loadFixtures(t)
	seen := map[string]bool{}
	for _, fixture := range fixtures {
		if fixture.Version != 1 {
			t.Errorf("fixture %q has version %d, want 1", fixture.Name, fixture.Version)
		}
		if seen[fixture.Name] {
			t.Errorf("fixture name %q is duplicated", fixture.Name)
		}
		seen[fixture.Name] = true
	}
}

// TestFixtureParity proves the Go struct captures every wire field with the
// exact wire meaning: each fixture fact must decode strictly (no unknown
// fields), validate, and re-marshal to a semantically identical document (no
// dropped, renamed, or defaulted fields).
func TestFixtureParity(t *testing.T) {
	fixtures, _ := loadFixtures(t)
	for _, fixture := range fixtures {
		t.Run(fixture.Name, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader(fixture.Fact))
			decoder.DisallowUnknownFields()
			var fact ledgerfact.DecisionFact
			if err := decoder.Decode(&fact); err != nil {
				t.Fatalf("strict decode: %v", err)
			}
			if err := fact.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}

			remarshalled, err := json.Marshal(fact)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got, want map[string]any
			if err := json.Unmarshal(remarshalled, &got); err != nil {
				t.Fatalf("decode re-marshalled fact: %v", err)
			}
			if err := json.Unmarshal(fixture.Fact, &want); err != nil {
				t.Fatalf("decode original fact: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("re-marshalled fact diverges from wire fixture\ngot:  %s\nwant: %s", remarshalled, fixture.Fact)
			}
		})
	}
}

func TestValidateRejectsContractViolations(t *testing.T) {
	fixtures, _ := loadFixtures(t)
	baseline := func(t *testing.T) ledgerfact.DecisionFact {
		t.Helper()
		for _, fixture := range fixtures {
			if fixture.Name != "enforce-evaluated-allow-permit" {
				continue
			}
			var fact ledgerfact.DecisionFact
			if err := json.Unmarshal(fixture.Fact, &fact); err != nil {
				t.Fatalf("decode baseline fact: %v", err)
			}
			return fact
		}
		t.Fatal("baseline fixture missing")
		return ledgerfact.DecisionFact{}
	}

	cases := map[string]func(fact *ledgerfact.DecisionFact){
		"authority marker as reason code": func(fact *ledgerfact.DecisionFact) {
			fact.ReasonCode = cedareval.ReasonObserveNonAuthoritative
		},
		"unknown reason code": func(fact *ledgerfact.DecisionFact) {
			fact.ReasonCode = "future_unrecognized_reason"
		},
		"non-finite risk score": func(fact *ledgerfact.DecisionFact) {
			value := math.NaN()
			evaluator := "test-judge"
			fact.Risk = &ledgerfact.Risk{Status: ledgerfact.RiskStatusEvaluated, Evaluator: &evaluator, Score: &value}
		},
		"non-finite risk confidence": func(fact *ledgerfact.DecisionFact) {
			value := math.Inf(1)
			evaluator := "test-judge"
			fact.Risk = &ledgerfact.Risk{Status: ledgerfact.RiskStatusEvaluated, Evaluator: &evaluator, Confidence: &value}
		},
		"cedar action without evaluation": func(fact *ledgerfact.DecisionFact) {
			fact.EvaluationState = cedareval.EvaluationStateFailed
		},
		"evaluated fact without provenance": func(fact *ledgerfact.DecisionFact) {
			fact.PolicyHash = nil
		},
		"enforce failing open": func(fact *ledgerfact.DecisionFact) {
			fact.EvaluationState = cedareval.EvaluationStateFailed
			fact.CedarAction = nil
			fact.ExecutionAction = cedareval.EffectiveExecutionActionAllow
			fact.ReasonCode = cedareval.ReasonEngineError
		},
		"enforced ask not denying": func(fact *ledgerfact.DecisionFact) {
			ask := cedareval.DerivedCedarActionAsk
			fact.CedarAction = &ask
			fact.ReasonCode = cedareval.ReasonAskUnavailable
			fact.ExecutionAction = cedareval.EffectiveExecutionActionAllow
		},
		"execution deny outside enforce": func(fact *ledgerfact.DecisionFact) {
			fact.AppliedMode = cedareval.RolloutModeObserve
			fact.ExecutionAction = cedareval.EffectiveExecutionActionDeny
			fact.ReasonCode = cedareval.ReasonExplicitForbid
			deny := cedareval.DerivedCedarActionDeny
			fact.CedarAction = &deny
		},
		"disabled deployment with provenance": func(fact *ledgerfact.DecisionFact) {
			fact.AppliedMode = cedareval.RolloutModeDisabled
		},
		"missing tool call id": func(fact *ledgerfact.DecisionFact) {
			fact.ToolCallID = ""
		},
		"unsorted determining policy ids": func(fact *ledgerfact.DecisionFact) {
			fact.DeterminingPolicyIDs = []string{"policyB", "policyA"}
		},
		"decision evidence disagreeing with the verdict": func(fact *ledgerfact.DecisionFact) {
			code := cedareval.ReasonDefaultDeny
			fact.Evidence.DecisionReasonCode = &code
		},
		"evaluated fact without principal evidence": func(fact *ledgerfact.DecisionFact) {
			fact.Evidence.EvaluationPrincipal = nil
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fact := baseline(t)
			mutate(&fact)
			if err := fact.Validate(); err == nil {
				t.Fatal("expected validation to fail")
			}
		})
	}
}
