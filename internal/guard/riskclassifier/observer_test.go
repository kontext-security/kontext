package riskclassifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordCollector struct {
	mu      sync.Mutex
	records []Record
}

func (c *recordCollector) sink(_ context.Context, record Record) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.records = append(c.records, record)
	return nil
}

func (c *recordCollector) wait(t *testing.T, want int) []Record {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		count := len(c.records)
		records := append([]Record(nil), c.records...)
		c.mu.Unlock()
		if count >= want {
			return records
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d records", want)
	return nil
}

func newTestObserver(t *testing.T, guardrail *Guardrail, collector *recordCollector) *Observer {
	t.Helper()
	svm, err := LoadSVM()
	if err != nil {
		t.Fatalf("load svm: %v", err)
	}
	observer := NewObserver(ObserverOptions{
		SVM:       svm,
		Guardrail: guardrail,
		Sink:      collector.sink,
		Redact: func(value string) string {
			return strings.ReplaceAll(value, "hunter2", "[redacted-credential]")
		},
	})
	if observer == nil {
		t.Fatal("observer construction failed")
	}
	t.Cleanup(observer.Close)
	return observer
}

func TestObserverRecordsBothModels(t *testing.T) {
	server := newGuardrailServer(t, "RISKY", nil)
	defer server.Close()
	guardrail, err := NewGuardrail(GuardrailOptions{BaseURL: server.URL, Model: "qwen2.5-0.5b"})
	if err != nil {
		t.Fatalf("new guardrail: %v", err)
	}
	collector := &recordCollector{}
	observer := newTestObserver(t, guardrail, collector)

	observer.RecordPrompt("sess_1", "wipe the box with hunter2")
	observer.Observe(ObserveInput{
		ActionID:  "act_1",
		SessionID: "sess_1",
		ToolUseID: "tu_1",
		Agent:     "claude",
		Command:   "rm -rf / --no-preserve-root hunter2",
	})

	record := collector.wait(t, 1)[0]
	if record.ActionID != "act_1" || record.SessionID != "sess_1" {
		t.Fatalf("record identity: %+v", record)
	}
	if strings.Contains(record.Command, "hunter2") || !strings.Contains(record.Command, "[redacted-credential]") {
		t.Fatalf("command not redacted: %q", record.Command)
	}
	if strings.Contains(record.AgentTask, "hunter2") {
		t.Fatalf("agent task not redacted: %q", record.AgentTask)
	}
	if record.CommandHash == "" || len(record.CommandHash) != 64 {
		t.Fatalf("command hash = %q", record.CommandHash)
	}
	if record.SVM == nil || record.SVM.ModelVersion == "" {
		t.Fatalf("svm verdict missing: %+v", record.SVM)
	}
	if record.LLM == nil || record.LLM.Verdict != VerdictRisky || record.LLM.Cached {
		t.Fatalf("llm verdict wrong: %+v", record.LLM)
	}
	if record.Enforced {
		t.Fatal("record must not be enforced")
	}
	if record.UserFeedback != "" {
		t.Fatal("record must start without feedback")
	}
}

func TestObserverCachesVerbatimRepeats(t *testing.T) {
	var calls int
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": "SAFE"}}},
		})
	}))
	defer server.Close()

	guardrail, err := NewGuardrail(GuardrailOptions{BaseURL: server.URL, Model: "qwen2.5-0.5b"})
	if err != nil {
		t.Fatalf("new guardrail: %v", err)
	}
	collector := &recordCollector{}
	observer := newTestObserver(t, guardrail, collector)

	// Fill the cache with the first record before sending repeats: concurrent
	// workers racing an identical fresh command may each miss, by design.
	observer.Observe(ObserveInput{ActionID: "act_a", SessionID: "sess_1", Command: "git status"})
	collector.wait(t, 1)
	observer.Observe(ObserveInput{ActionID: "act_b", SessionID: "sess_1", Command: "git status"})
	observer.Observe(ObserveInput{ActionID: "act_c", SessionID: "sess_1", Command: "git status"})
	records := collector.wait(t, 3)

	mu.Lock()
	llmCalls := calls
	mu.Unlock()
	if llmCalls != 1 {
		t.Fatalf("llm calls = %d, want 1 (cache misses)", llmCalls)
	}
	cachedCount := 0
	for _, record := range records {
		if record.LLM == nil {
			t.Fatalf("llm verdict missing: %+v", record)
		}
		if record.LLM.Cached {
			cachedCount++
		}
	}
	if cachedCount != 2 {
		t.Fatalf("cached records = %d, want 2", cachedCount)
	}
}

func TestObserverRecordsGuardrailFailureAsError(t *testing.T) {
	collector := &recordCollector{}
	observer := newTestObserver(t, nil, collector)

	observer.Observe(ObserveInput{ActionID: "act_1", SessionID: "sess_1", Command: "ls"})
	record := collector.wait(t, 1)[0]
	if record.LLM != nil {
		t.Fatalf("llm should be absent: %+v", record.LLM)
	}
	if record.LLMError == "" {
		t.Fatal("llm error missing")
	}
	if record.SVM == nil {
		t.Fatal("svm must still run without guardrail")
	}
}

func TestObserverCloseIsSafeUnderConcurrentObserve(t *testing.T) {
	collector := &recordCollector{}
	observer := newTestObserver(t, nil, collector)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				observer.Observe(ObserveInput{ActionID: "act", SessionID: "sess", Command: "ls"})
			}
		}()
	}
	observer.Close()
	wg.Wait()
	observer.Observe(ObserveInput{ActionID: "act", SessionID: "sess", Command: "ls"})
}
