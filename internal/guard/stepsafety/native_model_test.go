package stepsafety

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"runtime"
	"slices"
	"testing"
	"time"
)

func nativeTestModel(t *testing.T) (*nativeModel, *tokenizer) {
	t.Helper()
	started := time.Now()
	// Race instrumentation walks the large checkpoint much more slowly than
	// release builds. This test budget does not change the production deadline.
	backend, err := newNativeBackend(context.Background(), normalizeConfig(Config{StartupTimeout: 2 * time.Minute}))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native model initialization: %s", time.Since(started))
	return backend.model, backend.tokenizer
}

func frozenPacked(t *testing.T, tok *tokenizer, c historyGoldenCase) packedInput {
	t.Helper()
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
	var selected [4][]int64
	for i, field := range fields {
		ids, err := tok.encode(context.Background(), field)
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
			t.Fatal("frozen token hash differs")
		}
	}
	return packedInput{IDs: ids, Mask: mask}
}

func TestNativeLinearAgainstScalar(t *testing.T) {
	for _, shape := range [][3]int{{1, 2, 384}, {3, 9, 7}, {4, 8, 64}, {5, 17, 129}, {31, 384, 64}, {8, 1536, 384}} {
		rows, out, in := shape[0], shape[1], shape[2]
		x, w := make([]float32, rows*in), make([]float32, out*in)
		for i := range x {
			x[i] = float32(math.Sin(float64(i) * 0.73))
		}
		for i := range w {
			w[i] = float32(math.Cos(float64(i) * 0.21))
		}
		l := prepareNativeLinear(nativeLinear{weight: w, in: in, out: out})
		got := nativeLinearProduct(l, x, rows)
		for i := 0; i < rows; i++ {
			for j := 0; j < out; j++ {
				var want float64
				for k := 0; k < in; k++ {
					want += float64(x[i*in+k]) * float64(w[j*in+k])
				}
				if math.Abs(float64(got[i*out+j])-want) > 2e-4 {
					t.Fatalf("shape %v row %d col %d: %g want %g", shape, i, j, got[i*out+j], want)
				}
			}
		}
	}
}

func TestNativeEmbeddedWorksWithoutInstalledFiles(t *testing.T) {
	t.Setenv("KONTEXT_STEP_SAFETY_SHADOW", "")
	t.Setenv("KONTEXT_STEP_SAFETY_MODEL_DIR", "/nonexistent/merlin")
	root := t.TempDir()
	cfg, err := ConfigFromEnv(root + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Timeout = 5 * time.Second
	cfg.StartupTimeout = 2 * time.Minute
	e := New(context.Background(), cfg)
	defer e.Close()
	h := e.Health(context.Background())
	if h.Status != "ready" || h.Device != "go-cpu" {
		t.Fatalf("health=%+v", h)
	}
	result := e.Evaluate(context.Background(), Input{UserRequest: "What is the file size?", ToolName: "delete_file", ToolArguments: map[string]any{"file_id": "a"}})
	if result.ErrorCode != "" || result.UnsafeProbability == nil || result.Enforced {
		t.Fatalf("result=%+v", result)
	}
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 0 {
		t.Fatalf("embedded backend unexpectedly wrote files: %v %v", files, err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if e.Health(context.Background()).Status != "unavailable" {
		t.Fatal("closed backend still ready")
	}
}

func TestNativeCancellationReleasesSlot(t *testing.T) {
	b, err := newNativeBackend(context.Background(), normalizeConfig(Config{StartupTimeout: 2 * time.Minute}))
	if err != nil {
		t.Fatal(err)
	}
	e := NewWithBackend(b, 5*time.Second, 1, ModelVersion)
	defer e.Close()
	input := Input{UserRequest: "What is the file size?", ToolName: "delete_file", ToolArguments: map[string]any{"file_id": "a"}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	first := e.Evaluate(ctx, input)
	if first.ErrorCode != ErrorTimeout || first.UnsafeProbability != nil {
		t.Fatalf("cancelled=%+v", first)
	}
	next := e.Evaluate(context.Background(), input)
	if next.ErrorCode != "" || next.UnsafeProbability == nil {
		t.Fatalf("next=%+v", next)
	}
}

func TestNativeRejectsInvalidInput(t *testing.T) {
	for _, length := range []int{0, 1, 511, 513} {
		if _, err := nativeSequenceLength(packedInput{IDs: make([]int64, length), Mask: make([]int64, length)}); err == nil {
			t.Fatal("accepted invalid shape")
		}
	}
	p := packedInput{IDs: make([]int64, 512), Mask: make([]int64, 512)}
	if _, err := nativeSequenceLength(p); err == nil {
		t.Fatal("accepted empty mask")
	}
	p.Mask[0], p.Mask[2] = 1, 1
	if _, err := nativeSequenceLength(p); err == nil {
		t.Fatal("accepted hole in mask")
	}
	p.Mask[2] = 0
	p.IDs[0] = 128005
	if _, err := nativeSequenceLength(p); err == nil {
		t.Fatal("accepted invalid token")
	}
}

func TestNativeConcurrentInference(t *testing.T) {
	m, tok := nativeTestModel(t)
	cases := loadHistoryGoldenFixture(t).Cases
	inputs := []packedInput{frozenPacked(t, tok, cases[0]), frozenPacked(t, tok, cases[5])}
	type result struct {
		value InferenceResult
		err   error
		index int
	}
	wants := make([][2]float64, len(inputs))
	for i, p := range inputs {
		got, err := m.infer(context.Background(), p)
		if err != nil {
			t.Fatal(err)
		}
		wants[i] = got.Logits
	}
	results := make(chan result, len(inputs))
	for i, p := range inputs {
		go func(i int, p packedInput) { v, err := m.infer(context.Background(), p); results <- result{v, err, i} }(i, p)
	}
	for range inputs {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		want := wants[r.index]
		for j := range want {
			if math.Abs(r.value.Logits[j]-want[j]) > 2e-5 {
				t.Fatalf("concurrent output changed: %v want %v", r.value.Logits, want)
			}
		}
	}
}

// Timing is reported, not asserted: CI machines have different CPU budgets.
func TestNativeLatency(t *testing.T) {
	if os.Getenv("KONTEXT_MERLIN_BENCHMARK") != "1" {
		t.Skip("set KONTEXT_MERLIN_BENCHMARK=1 for latency measurements")
	}
	m, tok := nativeTestModel(t)
	short, err := packInput(context.Background(), tok, Input{UserRequest: "Inspect the repository and summarize the current configuration.", InteractionHistory: "[]", ToolName: "Bash", ToolArguments: map[string]any{"command": "git status --short"}})
	if err != nil {
		t.Fatal(err)
	}
	full := packedInput{IDs: make([]int64, 512), Mask: make([]int64, 512)}
	for i := range full.IDs {
		full.IDs[i] = int64(4 + (i*997+17)%127990)
		full.Mask[i] = 1
	}
	full.IDs[0] = 1
	for _, tc := range []struct {
		name string
		p    packedInput
	}{{"short", short}, {"full_512", full}} {
		t.Run(tc.name, func(t *testing.T) {
			_, _ = m.infer(context.Background(), tc.p)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			var times []float64
			for i := 0; i < 30; i++ {
				start := time.Now()
				_, err := m.infer(context.Background(), tc.p)
				if err != nil {
					t.Fatal(err)
				}
				times = append(times, float64(time.Since(start).Microseconds())/1000)
			}
			runtime.ReadMemStats(&after)
			slices.Sort(times)
			t.Logf("n=30 p50=%.2fms p95=%.2fms max=%.2fms allocations=%.2fMiB/call heap=%.2fMiB", times[15], times[28], times[29], float64(after.TotalAlloc-before.TotalAlloc)/30/(1<<20), float64(after.HeapAlloc)/(1<<20))
		})
	}
}
