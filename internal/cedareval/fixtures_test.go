package cedareval_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/kontext-security/kontext/internal/agent"
	"github.com/kontext-security/kontext/internal/agent/claude"
	"github.com/kontext-security/kontext/internal/agent/codex"
	"github.com/kontext-security/kontext/internal/agent/cowork"
	"github.com/kontext-security/kontext/internal/cedareval"
)

const portableFixtureContractVersion = 1

var fixtureDigests = map[string]string{
	"authorization-v1.json":          "c7f8aaf5da2acbf9a5d832ebf2bcf3ca531a617cdea3a6aed1b6b1840c4735b5",
	"context-errors-v1.json":         "945e6be23af02aa4d0c7bd382f5963b6342f46a02602bfbc8f134ae283b6773e",
	"decision-contract-v1.json":      "8d33cd7924de64b9000c18fdc3cb532250653f768e2a65c7acb001c26376a3c4",
	"decision-mapping-v1.json":       "7a0ba0b761b13759ef1a5ffefb155c7a066412b0115227f928529546a337e0b2",
	"evaluation-errors-v1.json":      "aef0f751ebf54625b4f516f67f37b58a59042a03fd684614172736a91c07a763",
	"hashing-v1.json":                "5179f41ae61872ee9f6a048cba4592dc12c0267fc8c8699a0c2afa886da62775",
	"validation-diagnostics-v1.json": "0462b65afce89bb20916812d5310f619161d884e850d231b160f94bb0a026ba0",
}

type authorizationFixture struct {
	Version     int                    `json:"version"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Policies    []string               `json:"policies"`
	Request     cedareval.ToolUseInput `json:"request"`
	Expected    struct {
		Decision             cedareval.Decision            `json:"decision"`
		Ask                  bool                          `json:"ask"`
		DeterminingPolicyIDs []string                      `json:"determiningPolicyIds"`
		ContextDiagnostics   []cedareval.ContextDiagnostic `json:"contextDiagnostics"`
	} `json:"expected"`
}

type contextErrorFixture struct {
	Version        int            `json:"version"`
	Name           string         `json:"name"`
	ToolInput      map[string]any `json:"toolInput"`
	InputGenerator *struct {
		Kind   string `json:"kind"`
		Depth  int    `json:"depth"`
		Length int    `json:"length"`
	} `json:"inputGenerator"`
	ExpectedCode string `json:"expectedCode"`
	ExpectedPath string `json:"expectedPath"`
}

type evaluationErrorFixture struct {
	Version     int                    `json:"version"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Policies    []string               `json:"policies"`
	Request     cedareval.ToolUseInput `json:"request"`
	Expected    struct {
		Decision                      cedareval.Decision                 `json:"decision"`
		EngineErrorCount              int                                `json:"engineErrorCount"`
		DeterminingPolicyIDs          []string                           `json:"determiningPolicyIds"`
		ContextDiagnostics            []cedareval.ContextDiagnostic      `json:"contextDiagnostics"`
		ObserveCurrentAuthorityAction cedareval.EffectiveExecutionAction `json:"observeCurrentAuthorityAction"`
		Observe                       cedareval.DecisionMapping          `json:"observe"`
		Enforce                       cedareval.DecisionMapping          `json:"enforce"`
	} `json:"expected"`
}

type hashFixture struct {
	Version             int                           `json:"version"`
	Name                string                        `json:"name"`
	PolicyText          string                        `json:"policyText"`
	RolloutMode         string                        `json:"rolloutMode"`
	EvaluationPrincipal cedareval.EvaluationPrincipal `json:"evaluationPrincipal"`
	ExpectedPolicyHash  string                        `json:"expectedPolicyHash"`
	ExpectedPreimage    string                        `json:"expectedDeploymentPreimage"`
	ExpectedIdentity    string                        `json:"expectedDeploymentIdentity"`
}

func TestPortableFixtureProvenance(t *testing.T) {
	t.Parallel()

	if portableFixtureContractVersion != cedareval.RequestContractVersion {
		t.Fatalf(
			"fixture contract version = %d, want request contract version %d",
			portableFixtureContractVersion,
			cedareval.RequestContractVersion,
		)
	}
	entries, err := os.ReadDir(filepath.Join("testdata", "portable", "v1"))
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if _, ok := fixtureDigests[entry.Name()]; !ok {
			t.Errorf("portable fixture %q has no pinned digest", entry.Name())
		}
	}
	for name, expected := range fixtureDigests {
		name := name
		expected := expected
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			contents, err := os.ReadFile(filepath.Join("testdata", "portable", "v1", name))
			if err != nil {
				t.Fatalf("ReadFile() error = %v", err)
			}
			sum := sha256.Sum256(contents)
			if got := hex.EncodeToString(sum[:]); got != expected {
				t.Fatalf("fixture digest = %s, want %s", got, expected)
			}
		})
	}
}

func TestPortableAuthorizationFixtures(t *testing.T) {
	var fixtures []authorizationFixture
	readFixture(t, "authorization-v1.json", &fixtures)

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			evaluator, err := cedareval.New(strings.Join(fixture.Policies, "\n\n"))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			result, err := evaluator.Evaluate(fixture.Request)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if result.Decision != fixture.Expected.Decision {
				t.Errorf("Decision = %q, want %q", result.Decision, fixture.Expected.Decision)
			}
			if result.Ask != fixture.Expected.Ask {
				t.Errorf("Ask = %v, want %v", result.Ask, fixture.Expected.Ask)
			}
			if !reflect.DeepEqual(result.DeterminingPolicyIDs, fixture.Expected.DeterminingPolicyIDs) {
				t.Errorf("DeterminingPolicyIDs = %v, want %v", result.DeterminingPolicyIDs, fixture.Expected.DeterminingPolicyIDs)
			}
			if !reflect.DeepEqual(result.ContextDiagnostics, fixture.Expected.ContextDiagnostics) {
				t.Errorf("ContextDiagnostics = %v, want %v", result.ContextDiagnostics, fixture.Expected.ContextDiagnostics)
			}
			if len(result.EngineDiagnostics.Errors) != 0 {
				t.Errorf("EngineDiagnostics.Errors = %v, want none", result.EngineDiagnostics.Errors)
			}
		})
	}
}

func TestPortableContextErrorFixtures(t *testing.T) {
	var fixtures []contextErrorFixture
	readFixture(t, "context-errors-v1.json", &fixtures)

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			_, _, err := cedareval.ConvertToolInput(contextErrorInput(t, fixture))
			var conversionError *cedareval.ConversionError
			if !errors.As(err, &conversionError) {
				t.Fatalf("ConvertToolInput() error = %v, want ConversionError", err)
			}
			if conversionError.Code != fixture.ExpectedCode || conversionError.Path != fixture.ExpectedPath {
				t.Fatalf(
					"ConversionError = (%q, %q), want (%q, %q)",
					conversionError.Code,
					conversionError.Path,
					fixture.ExpectedCode,
					fixture.ExpectedPath,
				)
			}
		})
	}
}

func TestPortableEvaluationErrorFixtures(t *testing.T) {
	var fixtures []evaluationErrorFixture
	readFixture(t, "evaluation-errors-v1.json", &fixtures)

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			evaluator, err := cedareval.New(strings.Join(fixture.Policies, "\n\n"))
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			result, err := evaluator.Evaluate(fixture.Request)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if result.Decision != fixture.Expected.Decision {
				t.Errorf("Decision = %q, want %q", result.Decision, fixture.Expected.Decision)
			}
			if len(result.EngineDiagnostics.Errors) != fixture.Expected.EngineErrorCount {
				t.Errorf("EngineDiagnostics.Errors count = %d, want %d", len(result.EngineDiagnostics.Errors), fixture.Expected.EngineErrorCount)
			}
			if !reflect.DeepEqual(result.DeterminingPolicyIDs, fixture.Expected.DeterminingPolicyIDs) {
				t.Errorf("DeterminingPolicyIDs = %v, want %v", result.DeterminingPolicyIDs, fixture.Expected.DeterminingPolicyIDs)
			}
			if !reflect.DeepEqual(result.ContextDiagnostics, fixture.Expected.ContextDiagnostics) {
				t.Errorf("ContextDiagnostics = %v, want %v", result.ContextDiagnostics, fixture.Expected.ContextDiagnostics)
			}

			principal := fixture.Request.EvaluationPrincipal
			evaluation := cedareval.EvaluationOutcome{
				State:  cedareval.EvaluationStateFailed,
				Reason: cedareval.ReasonEngineError,
			}
			observe, err := cedareval.MapDecision(cedareval.DecisionMappingInput{
				RolloutMode:            cedareval.RolloutModeObserve,
				CurrentAuthorityAction: fixture.Expected.ObserveCurrentAuthorityAction,
				EvaluationPrincipal:    &principal,
				Evaluation:             evaluation,
			})
			if err != nil {
				t.Fatalf("MapDecision(observe) error = %v", err)
			}
			if !reflect.DeepEqual(observe, fixture.Expected.Observe) {
				t.Errorf("MapDecision(observe) = %#v, want %#v", observe, fixture.Expected.Observe)
			}

			enforce, err := cedareval.MapDecision(cedareval.DecisionMappingInput{
				RolloutMode:         cedareval.RolloutModeEnforce,
				EnforcementReady:    true,
				EvaluationPrincipal: &principal,
				Evaluation:          evaluation,
			})
			if err != nil {
				t.Fatalf("MapDecision(enforce) error = %v", err)
			}
			if !reflect.DeepEqual(enforce, fixture.Expected.Enforce) {
				t.Errorf("MapDecision(enforce) = %#v, want %#v", enforce, fixture.Expected.Enforce)
			}
		})
	}
}

func contextErrorInput(t *testing.T, fixture contextErrorFixture) map[string]any {
	t.Helper()
	if fixture.InputGenerator == nil {
		return fixture.ToolInput
	}

	switch fixture.InputGenerator.Kind {
	case "nested-record":
		var value any = map[string]any{}
		for range fixture.InputGenerator.Depth {
			value = map[string]any{"value": value}
		}
		return value.(map[string]any)
	case "wide-array":
		values := make([]any, fixture.InputGenerator.Length)
		for i := range values {
			values[i] = 0
		}
		return map[string]any{"values": values}
	default:
		t.Fatalf("unsupported input generator %q", fixture.InputGenerator.Kind)
		return nil
	}
}

func TestPortableHashFixtures(t *testing.T) {
	var fixtures []hashFixture
	readFixture(t, "hashing-v1.json", &fixtures)

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			t.Parallel()
			policyHash := cedareval.ComputePolicyHash(fixture.PolicyText)
			if policyHash != fixture.ExpectedPolicyHash {
				t.Fatalf("ComputePolicyHash() = %q, want %q", policyHash, fixture.ExpectedPolicyHash)
			}
			input := cedareval.DeploymentIdentityInput{
				ResponseVersion:        1,
				RequestContractVersion: cedareval.RequestContractVersion,
				PolicyHash:             policyHash,
				RolloutMode:            fixture.RolloutMode,
				EvaluationPrincipal:    fixture.EvaluationPrincipal,
			}
			preimage, err := cedareval.DeploymentIdentityPreimage(input)
			if err != nil {
				t.Fatalf("DeploymentIdentityPreimage() error = %v", err)
			}
			if preimage != fixture.ExpectedPreimage {
				t.Errorf("DeploymentIdentityPreimage() = %q, want %q", preimage, fixture.ExpectedPreimage)
			}
			identity, err := cedareval.ComputeDeploymentIdentity(input)
			if err != nil {
				t.Fatalf("ComputeDeploymentIdentity() error = %v", err)
			}
			if identity != fixture.ExpectedIdentity {
				t.Errorf("ComputeDeploymentIdentity() = %q, want %q", identity, fixture.ExpectedIdentity)
			}
		})
	}
}

func TestRegisteredAdapterBoundaries(t *testing.T) {
	t.Parallel()

	policy := `@id("allow_input")
permit(principal, action == Kontext::Action::"ToolUse", resource == Kontext::Tool::"CustomTool")
when { context has risk && context.risk == decimal("1.25") };`
	evaluator, err := cedareval.New(policy)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	principal := cedareval.EvaluationPrincipal{
		EntityType: cedareval.PrincipalEntityType,
		EntityID:   "alice@example.com",
	}
	tests := []struct {
		name    string
		agent   agent.Agent
		payload string
	}{
		{
			name:    "claude",
			agent:   &claude.Claude{},
			payload: `{"hook_event_name":"PreToolUse","tool_name":"CustomTool","tool_input":{"risk":1.25}}`,
		},
		{
			name:    "cowork",
			agent:   &cowork.Cowork{},
			payload: `{"hook_event_name":"PreToolUse","tool_name":"CustomTool","tool_input":{"risk":1.25}}`,
		},
		{
			name:    "codex",
			agent:   &codex.Codex{},
			payload: `{"hook_event_name":"PreToolUse","tool_name":"CustomTool","tool_input":{"risk":1.25}}`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			event, err := tt.agent.DecodeHookInput([]byte(tt.payload))
			if err != nil {
				t.Fatalf("DecodeHookInput() error = %v", err)
			}
			input, err := cedareval.InputFromEvent(principal, event)
			if err != nil {
				t.Fatalf("InputFromEvent() error = %v", err)
			}
			result, err := evaluator.Evaluate(input)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if result.Decision != cedareval.DecisionAllow {
				t.Fatalf("Decision = %q, want allow", result.Decision)
			}
		})
	}
}

func TestEvaluatorDoesNotMutateInputAndSupportsConcurrentUse(t *testing.T) {
	t.Parallel()

	evaluator, err := cedareval.New(`@id("allow") permit(principal, action, resource);`)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	input := cedareval.ToolUseInput{
		EvaluationPrincipal: cedareval.EvaluationPrincipal{
			EntityType: cedareval.PrincipalEntityType,
			EntityID:   "alice@example.com",
		},
		ToolName: "CustomTool",
		ToolInput: map[string]any{
			"nested": map[string]any{"enabled": true},
			"values": []any{"one", "one", "two"},
			"unused": nil,
		},
	}
	original := cloneJSONMap(t, input.ToolInput)

	const workers = 32
	var waitGroup sync.WaitGroup
	errorsChannel := make(chan error, workers)
	for range workers {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			result, err := evaluator.Evaluate(input)
			if err != nil {
				errorsChannel <- err
				return
			}
			if result.Decision != cedareval.DecisionAllow {
				errorsChannel <- errors.New("unexpected deny")
			}
		}()
	}
	waitGroup.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		t.Errorf("concurrent Evaluate() error = %v", err)
	}
	if !reflect.DeepEqual(input.ToolInput, original) {
		t.Fatalf("Evaluate() mutated input: got %v, want %v", input.ToolInput, original)
	}
}

func readFixture(t *testing.T, name string, destination any) {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", "portable", "v1", name))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		t.Fatalf("Decode() trailing content error = %v", err)
	}

	type fixtureMetadata struct {
		Version int `json:"version"`
	}
	var metadata []fixtureMetadata
	if bytes.HasPrefix(bytes.TrimSpace(contents), []byte("{")) {
		var fixture fixtureMetadata
		if err := json.Unmarshal(contents, &fixture); err != nil {
			t.Fatalf("Decode() fixture metadata error = %v", err)
		}
		metadata = append(metadata, fixture)
	} else if err := json.Unmarshal(contents, &metadata); err != nil {
		t.Fatalf("Decode() fixture metadata error = %v", err)
	}
	for index, fixture := range metadata {
		if fixture.Version != portableFixtureContractVersion {
			t.Fatalf(
				"fixture %d version = %d, want %d",
				index,
				fixture.Version,
				portableFixtureContractVersion,
			)
		}
	}
}

func cloneJSONMap(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	contents, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	var clone map[string]any
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.UseNumber()
	if err := decoder.Decode(&clone); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	return clone
}
