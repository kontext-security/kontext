package stepsafety

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestScopedEffectContract(t *testing.T) {
	cases := []struct {
		tool   string
		args   map[string]any
		effect string
	}{
		{"mcp__x__DeleteRecord", map[string]any{"record_id": "a"}, "destructive_object_change"},
		{"get_delete_file_logs", map[string]any{"path": "a"}, ""},
		{"delete_file", map[string]any{"path": " "}, ""},
		{"delete_file", map[string]any{"path": "a", "dry_run": true}, ""},
		{"delete_file", map[string]any{"ids": []any{}}, ""},
		{"send_money", map[string]any{"amount": true, "recipient": "a"}, ""},
		{"send_money", map[string]any{"amount": json.Number("3.5"), "recipient": "a"}, "money_transfer"},
		{"send_money", map[string]any{"amount": math.Inf(1), "recipient": "a"}, ""},
		{"send_email", map[string]any{"recipients": []any{"a"}, "body": "Hello"}, "outgoing_message"},
		{"send_email", map[string]any{"recipients": []any{}, "body": "Hello"}, ""},
		{"share_file", map[string]any{"file_id": "a", "email": "example@example.invalid"}, "access_share"},
		{"WebSearch", map[string]any{"query": "delete_file send_money"}, ""},
		{"clock.sleep", map[string]any{"duration_ms": 1000.}, ""},
		{"mcp__cua_repl__js", map[string]any{"code": "delete_file(a)"}, ""},
	}
	for _, c := range cases {
		if got := recognizedScopeEffect(c.tool, c.args); got != c.effect {
			t.Fatalf("%s: %q want %q", c.tool, got, c.effect)
		}
	}
}

func TestScopedAuthorizationAndBounds(t *testing.T) {
	_, tok := nativeTestModel(t)
	base := Input{UserRequest: "Please delete that file.", ToolName: "delete_file", ToolArguments: map[string]any{"file_id": "example"}}
	if _, e := packScopedInput(context.Background(), tok, base); errorCode(e) != ErrorCompoundRequest {
		t.Fatalf("explicit authorization: %v", e)
	}
	base.UserRequest = ""
	if _, e := packScopedInput(context.Background(), tok, base); errorCode(e) != ErrorMissingRequest {
		t.Fatal(e)
	}
	base.UserRequest = "What is the file size?"
	base.ToolArguments = map[string]any{"file_id": strings.Repeat("word ", 500)}
	if _, e := packScopedInput(context.Background(), tok, base); errorCode(e) != ErrorActionTooLarge {
		t.Fatalf("silent action truncation: %v", e)
	}
	base.ToolArguments = map[string]any{"file_id": "a"}
	base.InteractionHistory = "[malformed"
	if _, e := packScopedInput(context.Background(), tok, base); errorCode(e) != ErrorInvalidHistory {
		t.Fatal(e)
	}
	base.InteractionHistory = "[]"
	base.UserRequest = strings.Repeat("x", maxPretokenizedFieldBytes+1)
	if _, e := packScopedInput(context.Background(), tok, base); errorCode(e) != ErrorInputTooLarge {
		t.Fatal(e)
	}
}

func TestScopedConcurrentInference(t *testing.T) {
	b, e := newNativeBackend(context.Background(), normalizeConfig(Config{}))
	if e != nil {
		t.Fatal(e)
	}
	input := Input{UserRequest: "What is the file size?", ToolName: "delete_file", ToolArguments: map[string]any{"file_id": "a"}}
	want, e := b.Infer(context.Background(), input)
	if e != nil {
		t.Fatal(e)
	}
	type answer struct {
		r InferenceResult
		e error
	}
	ch := make(chan answer, 3)
	for i := 0; i < 3; i++ {
		go func() { r, e := b.Infer(context.Background(), input); ch <- answer{r, e} }()
	}
	for i := 0; i < 3; i++ {
		a := <-ch
		if a.e != nil {
			t.Fatal(a.e)
		}
		if math.Abs(a.r.Logits[1]-want.Logits[1]) > 1e-5 {
			t.Fatal("concurrent inference differs")
		}
	}
}

func TestScopedRuntimeProfile(t *testing.T) {
	if os.Getenv("KONTEXT_MERLIN_BENCHMARK") != "1" {
		t.Skip("explicit benchmark opt-in")
	}
	b, e := newNativeBackend(context.Background(), normalizeConfig(Config{}))
	if e != nil {
		t.Fatal(e)
	}
	for _, long := range []bool{false, true} {
		request := "What is the file size?"
		history := "[]"
		schema := ""
		if long {
			// Keep informational request fixed while profiling long context.
			history = `[{"tool":"lookup","observation":"` + strings.Repeat("untrusted observation ", 500) + `"}]`
			schema = strings.Repeat("schema details ", 500)
		}
		input := Input{UserRequest: request, ToolName: "delete_file", ToolArguments: map[string]any{"file_id": "a"}, InteractionHistory: history, AvailableToolSchemas: schema}
		for i := 0; i < 3; i++ {
			if _, e = b.Infer(context.Background(), input); e != nil {
				t.Fatal(e)
			}
		}
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		times := []float64{}
		start := time.Now()
		for i := 0; i < 50; i++ {
			now := time.Now()
			if _, e = b.Infer(context.Background(), input); e != nil {
				t.Fatal(e)
			}
			times = append(times, float64(time.Since(now).Microseconds())/1000)
		}
		elapsed := time.Since(start).Seconds()
		runtime.ReadMemStats(&after)
		slices.Sort(times)
		t.Logf("long=%t p50_ms=%g p95_ms=%g p99_ms=%g throughput=%g heap_mib=%g alloc_per_call=%d", long, times[24], times[47], times[49], 50/elapsed, float64(after.HeapAlloc)/(1<<20), (after.TotalAlloc-before.TotalAlloc)/50)
	}
}
