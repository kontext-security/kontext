package riskclassifier

import (
	"context"
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

func newTestObserver(t *testing.T, collector *recordCollector) *Observer {
	t.Helper()
	svm, err := LoadSVM()
	if err != nil {
		t.Fatalf("load svm: %v", err)
	}
	observer := NewObserver(ObserverOptions{
		SVM:  svm,
		Sink: collector.sink,
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

func TestObserverRecordsVerdict(t *testing.T) {
	collector := &recordCollector{}
	observer := newTestObserver(t, collector)

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
	if len(record.CommandHash) != 64 {
		t.Fatalf("command hash = %q", record.CommandHash)
	}
	if record.SVM == nil || record.SVM.ModelVersion == "" {
		t.Fatalf("svm verdict missing: %+v", record.SVM)
	}
	if record.SVM.Threshold == 0 {
		t.Fatalf("svm threshold not recorded: %+v", record.SVM)
	}
	if record.Enforced {
		t.Fatal("record must not be enforced")
	}
	if record.UserFeedback != "" {
		t.Fatal("record must start without feedback")
	}
}

func TestObserverIgnoresIncompleteInput(t *testing.T) {
	collector := &recordCollector{}
	observer := newTestObserver(t, collector)

	for _, input := range []ObserveInput{
		{ActionID: "", SessionID: "sess_1", Command: "ls"},
		{ActionID: "act_1", SessionID: "", Command: "ls"},
		{ActionID: "act_1", SessionID: "sess_1", Command: ""},
	} {
		observer.Observe(input)
	}
	// A well-formed record behind them proves the queue drained past the
	// rejected ones rather than merely lagging.
	observer.Observe(ObserveInput{ActionID: "act_ok", SessionID: "sess_1", Command: "ls"})
	records := collector.wait(t, 1)
	if len(records) != 1 || records[0].ActionID != "act_ok" {
		t.Fatalf("unexpected records: %+v", records)
	}
}

func TestObserverCloseIsSafeUnderConcurrentObserve(t *testing.T) {
	collector := &recordCollector{}
	observer := newTestObserver(t, collector)

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
	// Observing after Close must be a no-op, not a send on a closed channel.
	observer.Observe(ObserveInput{ActionID: "act", SessionID: "sess", Command: "ls"})
}
