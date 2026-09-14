package stepsafety

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These integration tests use only Go and the installed ONNX artifacts. The
// Python reference outputs are frozen data; CI unit tests need no runtime.
func parityModelDir(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("KONTEXT_STEP_SAFETY_PARITY_MODEL_DIR")
	if dir == "" {
		t.Skip("set KONTEXT_STEP_SAFETY_PARITY_MODEL_DIR to an installed ONNX model")
	}
	if err := ValidateModelDir(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGoTokenizerMatchesHuggingFace(t *testing.T) {
	dir := parityModelDir(t)
	tokenizer, err := loadTokenizer(filepath.Join(dir, "tokenizer.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		TokenizerSHA256 string `json:"tokenizer_sha256"`
		Cases           []struct {
			Text string
			IDs  []int64
		}
	}
	data, err := os.ReadFile("testdata/tokenizer_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if hash, err := fileSHA256(filepath.Join(dir, "tokenizer.json")); err != nil || hash != fixture.TokenizerSHA256 {
		t.Fatal("tokenizer fixture provenance mismatch")
	}
	for i, c := range fixture.Cases {
		ids, err := tokenizer.encode(context.Background(), c.Text)
		if err != nil || !slices.Equal(ids, c.IDs) {
			t.Fatalf("case %d (%q): ids %v, want %v, err %v", i, c.Text, ids, c.IDs, err)
		}
	}
	t.Logf("matched %d HF tokenizer reference vectors", len(fixture.Cases))
}

func TestONNXMatchesFrozenCheckpoint(t *testing.T) {
	dir := parityModelDir(t)
	backend, err := newONNXBackend(context.Background(), normalizeConfig(Config{ModelDir: dir, ModelVersion: ModelVersion}))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	for _, c := range loadHistoryGoldenFixture(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			history := c.NormalizedHistory
			if c.GeneratedLongObservationTokens > 0 {
				var err error
				history, err = serializeHistory(generatedLongObservation(c.GeneratedLongObservationTokens))
				if err != nil {
					t.Fatal(err)
				}
			}
			arguments, err := compactSortedJSON(c.ToolArguments)
			if err != nil {
				t.Fatal(err)
			}
			schema, err := schemaText(c.AvailableToolSchemas)
			if err != nil {
				t.Fatal(err)
			}
			fields := [4]string{c.UserRequest, history, "[TOOL_NAME]\n" + c.ToolName + "\n[ARGUMENTS]\n" + arguments, schema}
			// Reconstruct the frozen TRAINING packer in the test only. Production
			// deliberately excludes file tools and never head/tail slices actions.
			var selected [4][]int64
			for i, field := range fields {
				ids, err := backend.tokenizer.encode(context.Background(), field)
				if err != nil {
					t.Fatal(err)
				}
				budget := fieldBudgets[i]
				if len(ids) > budget {
					if i == 0 {
						ids = ids[:budget]
					} else {
						head := (budget + 1) / 2
						ids = append(slices.Clone(ids[:head]), ids[len(ids)-(budget-head):]...)
					}
				}
				selected[i] = ids
			}
			ids, mask := assembleTokens(selected)
			for _, check := range []struct {
				value []int64
				hash  string
			}{{ids, c.PackedSHA256}, {mask, c.MaskSHA256}} {
				encoded, err := json.Marshal(check.value)
				if err != nil || sha256String(string(encoded)) != check.hash {
					t.Fatalf("packed token contract changed: got %s, want %s", sha256String(string(encoded)), check.hash)
				}
			}
			result, err := backend.inferPacked(context.Background(), packedInput{IDs: ids, Mask: mask})
			if err != nil {
				t.Fatal(err)
			}
			for i, want := range c.Logits {
				if math.Abs(result.Logits[i]-want) > 2e-5 {
					t.Errorf("logit %d: %.9f, want %.9f", i, result.Logits[i], want)
				}
			}
		})
	}
}

func TestONNXTimeoutThenNextRequest(t *testing.T) {
	dir := parityModelDir(t)
	backend, err := newONNXBackend(context.Background(), normalizeConfig(Config{ModelDir: dir, ModelVersion: ModelVersion}))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	evaluator := NewWithBackend(backend, 5*time.Second, 1, ModelVersion)
	input := Input{UserRequest: "Show repository status", InteractionHistory: "[]", ToolName: "Bash", ToolArguments: map[string]any{"command": "git status --short"}}
	// A real native call can finish after the deadline; that result must be
	// discarded and the next request must get its own result.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	started := time.Now()
	first := evaluator.Evaluate(ctx, input)
	if first.ErrorCode != ErrorTimeout || first.UnsafeProbability != nil {
		t.Fatalf("first = %+v", first)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("deadline took %s", elapsed)
	}
	second := evaluator.Evaluate(context.Background(), input)
	if second.ErrorCode != "" || second.UnsafeProbability == nil {
		t.Fatalf("next inference = %+v", second)
	}
}

func TestONNXContextHistoryMatchesTrainingPacking(t *testing.T) {
	dir := parityModelDir(t)
	backend, err := newONNXBackend(context.Background(), normalizeConfig(Config{ModelDir: dir, ModelVersion: ModelVersion}))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	evaluator := NewWithBackend(backend, defaultTimeout, 1, ModelVersion)
	var fixture struct {
		TokenizerSHA256 string `json:"tokenizer_sha256"`
		Cases           []struct {
			GeneratedWords int        `json:"generated_words"`
			PackedSHA256   string     `json:"packed_sha256"`
			Logits         [2]float64 `json:"logits"`
		} `json:"cases"`
	}
	data, err := os.ReadFile("testdata/context_history_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if hash, err := fileSHA256(filepath.Join(dir, "tokenizer.json")); err != nil || hash != fixture.TokenizerSHA256 {
		t.Fatal("history fixture tokenizer provenance mismatch")
	}
	for _, c := range fixture.Cases {
		t.Run(strconv.Itoa(c.GeneratedWords), func(t *testing.T) {
			store := NewContextStore()
			store.RecordUserRequest("s", "Summarize the search results.")
			entry := generatedLongObservation(c.GeneratedWords)[0]
			entry.ToolName = "search"
			entry.ToolArguments = map[string]any{"query": "public docs"}
			store.RecordInteraction("s", entry)
			store.RecordInteraction("s", HistoryEntry{ToolName: "Read", ToolResponse: map[string]any{"content": strings.Repeat("excluded ", 9000)}})
			snapshot := store.SnapshotWithCoverage("s")
			if len(snapshot.InteractionHistory) <= 4096 || len(snapshot.InteractionHistory) > maxHistoryBytes {
				t.Fatalf("supported history discarded: bytes=%d", len(snapshot.InteractionHistory))
			}
			input := Input{UserRequest: snapshot.UserRequest, InteractionHistory: snapshot.InteractionHistory, HistoryOmitted: snapshot.HistoryOmitted, ToolName: "summarize", ToolArguments: map[string]any{"topic": "public docs"}}
			packed, err := packInput(context.Background(), backend.tokenizer, input)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(packed.IDs)
			if err != nil || sha256String(string(encoded)) != c.PackedSHA256 {
				t.Fatalf("cached history differs from HF training tokens: got %s, want %s", sha256String(string(encoded)), c.PackedSHA256)
			}
			result := evaluator.Evaluate(context.Background(), input)
			want := CalibratedProbability(c.Logits[1] - c.Logits[0])
			if result.ErrorCode != "" || result.UnsafeProbability == nil || !result.HistoryOmitted || result.Enforced {
				t.Fatalf("shadow result = %+v", result)
			}
			if math.Abs(*result.UnsafeProbability-want) > 2e-5 {
				t.Fatalf("probability = %.9f, want %.9f", *result.UnsafeProbability, want)
			}
		})
	}
}

// A small paired dataset reports useful signals and coverage, not a model
// quality gate. Labels are illustrative and never used to tune the threshold.
// These are data strings only: no tool action in this fixture is executed.
func TestONNXScopedSmoke(t *testing.T) {
	dir := parityModelDir(t)
	backend, err := newONNXBackend(context.Background(), normalizeConfig(Config{ModelDir: dir, ModelVersion: ModelVersion}))
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	evaluator := NewWithBackend(backend, 5*time.Second, 1, ModelVersion)
	var fixture struct {
		Cases []struct {
			ID, Family string
			Label      int
			Input      Input
		}
	}
	data, err := os.ReadFile("testdata/scoped_smoke.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	type counts struct {
		Scored, TP, TN, FP, FN int
		Skipped                map[string]int
	}
	totals := map[string]*counts{}
	for _, c := range fixture.Cases {
		group := totals[c.Family]
		if group == nil {
			group = &counts{Skipped: map[string]int{}}
			totals[c.Family] = group
		}
		result := evaluator.Evaluate(context.Background(), c.Input)
		if result.ErrorCode != "" {
			switch result.ErrorCode {
			case ErrorExcludedTool, ErrorActionTooLarge, ErrorSchemaTooLarge, ErrorRequestTooLarge, ErrorInputTooLarge:
				group.Skipped[result.ErrorCode]++
				continue
			}
			t.Fatalf("%s inference failed: %+v", c.ID, result)
		}
		group.Scored++
		unsafe := result.ShadowDecision == DecisionUnsafe
		switch {
		case unsafe && c.Label == 1:
			group.TP++
		case unsafe:
			group.FP++
		case c.Label == 1:
			group.FN++
		default:
			group.TN++
		}
	}
	encoded, err := json.Marshal(totals)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("paired synthetic smoke (not a benchmark): %s", encoded)
}
