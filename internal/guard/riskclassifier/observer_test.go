package riskclassifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
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
	// Generous on purpose. This bounds how long a genuine failure takes to
	// report, not how fast a passing test runs, and the work behind these records
	// is linear in command length under -race on a shared CI runner.
	deadline := time.Now().Add(30 * time.Second)
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

// TestCommandHashCoversExactlyWhatIsStored: anything the hash covers but the row
// omits is a guessing oracle over the omitted part. The hash must therefore be
// taken over the redacted, truncated text that actually lands in the row.
func TestCommandHashCoversExactlyWhatIsStored(t *testing.T) {
	collector := &recordCollector{}
	observer := newTestObserver(t, collector)

	long := "echo " + strings.Repeat("x", storedCommandMaxBytes+512) + " tail-secret"
	observer.Observe(ObserveInput{ActionID: "act_long", SessionID: "sess", Command: long})
	record := collector.wait(t, 1)[0]

	if !record.CommandTruncated {
		t.Fatal("expected the command to be truncated")
	}
	want := sha256.Sum256([]byte(record.Command))
	if record.CommandHash != hex.EncodeToString(want[:]) {
		t.Error("hash does not cover exactly the stored command")
	}
	// Specifically, it must not cover the untruncated text.
	full := sha256.Sum256([]byte(long))
	if record.CommandHash == hex.EncodeToString(full[:]) {
		t.Error("hash covers the untruncated command, leaving an oracle over the dropped suffix")
	}
}

// A verdict must carry the task that was active when the command was
// intercepted. The prompt cache holds one entry per session, so resolving it in
// the worker instead would attach whatever prompt happened to be current by the
// time the item was processed — or nothing, if it had been evicted.
func TestAgentTaskIsCapturedAtIntakeNotAtProcessing(t *testing.T) {
	release := make(chan struct{})
	collector := &recordCollector{}
	observer := newObserverWithSink(t, func(ctx context.Context, record Record) error {
		<-release
		return collector.sink(ctx, record)
	})

	observer.RecordPrompt("sess_1", "first task")
	observer.Observe(ObserveInput{ActionID: "act_1", SessionID: "sess_1", Command: "ls -la"})

	// A new prompt lands while the first command is still queued, and the
	// session's single cache entry is overwritten.
	observer.RecordPrompt("sess_1", "second task")
	observer.Observe(ObserveInput{ActionID: "act_2", SessionID: "sess_1", Command: "pwd"})
	close(release)

	records := collector.wait(t, 2)
	tasks := map[string]string{}
	for _, record := range records {
		tasks[record.ActionID] = record.AgentTask
	}
	if tasks["act_1"] != "first task" {
		t.Errorf("act_1 task = %q, want %q", tasks["act_1"], "first task")
	}
	if tasks["act_2"] != "second task" {
		t.Errorf("act_2 task = %q, want %q", tasks["act_2"], "second task")
	}
}

// A worker that is mid-write when Close is called must finish unwinding before
// Close returns: the caller's next move is to close the SQLite store, and a
// write racing that teardown is a use-after-free on the database handle.
func TestCloseWaitsForWorkerBeforeReturning(t *testing.T) {
	defer swapDrainTimeout(50 * time.Millisecond)()

	entered := make(chan struct{})
	returned := make(chan struct{})
	observer := newObserverWithSink(t, func(ctx context.Context, _ Record) error {
		close(entered)
		// Hold the "write" open past the drain budget, then honour cancellation
		// the way a real SQLite call under a context does.
		<-ctx.Done()
		close(returned)
		return ctx.Err()
	})

	observer.Observe(ObserveInput{ActionID: "act_1", SessionID: "sess_1", Command: "ls -la"})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sink was never entered")
	}

	observer.Close()

	select {
	case <-returned:
	default:
		t.Fatal("Close returned while the sink write was still in flight")
	}
}

// The wait after cancellation is deliberately unbounded: a deadline there would
// mean returning mid-write, which is the exact hazard. A sink that takes longer
// than any grace period would have must still hold Close.
func TestCloseWaitsEvenWhenTheWriteOutlastsAnyGrace(t *testing.T) {
	defer swapDrainTimeout(10 * time.Millisecond)()

	entered := make(chan struct{})
	var unwound atomic.Bool
	observer := newObserverWithSink(t, func(ctx context.Context, _ Record) error {
		close(entered)
		<-ctx.Done()
		// Longer than any bounded grace this code has ever used.
		time.Sleep(3 * time.Second)
		unwound.Store(true)
		return ctx.Err()
	})

	observer.Observe(ObserveInput{ActionID: "act_1", SessionID: "sess_1", Command: "ls -la"})
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("sink was never entered")
	}

	observer.Close()
	if !unwound.Load() {
		t.Fatal("Close returned before the write finished unwinding")
	}
}

// Draining must not spend an inference per queued item: the budget is finite and
// the SVM verdict is the part worth keeping.
func TestShutdownShedsLLMButKeepsTheVerdict(t *testing.T) {
	guardrail, err := NewGuardrail(GuardrailOptions{
		BaseURL: "http://127.0.0.1:1",
		Model:   "qwen3-0.6b",
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("guardrail: %v", err)
	}

	collector := &recordCollector{}
	observer := newTestObserver(t, collector)
	observer.guardrail = guardrail
	// Stand where a worker stands after Close has flipped the flag but before
	// the queue has drained.
	observer.closed.Store(true)

	observer.process(queuedObservation{
		ObserveInput: ObserveInput{ActionID: "act_1", SessionID: "sess_1", Command: "rm -rf /"},
	})

	record := collector.wait(t, 1)[0]
	if record.SVM == nil {
		t.Fatalf("shutdown dropped the SVM verdict: %+v", record)
	}
	if record.LLM != nil {
		t.Fatalf("shutdown ran an inference: %+v", record.LLM)
	}
	if !strings.Contains(record.LLMError, "shutting down") {
		t.Fatalf("shutdown not recorded as the reason: %q", record.LLMError)
	}
}

func newObserverWithSink(t *testing.T, sink Sink) *Observer {
	t.Helper()
	svm, err := LoadSVM()
	if err != nil {
		t.Fatalf("load svm: %v", err)
	}
	observer := NewObserver(ObserverOptions{
		SVM:    svm,
		Sink:   sink,
		Redact: func(value string) string { return value },
	})
	if observer == nil {
		t.Fatal("observer construction failed")
	}
	t.Cleanup(observer.Close)
	return observer
}

func swapDrainTimeout(drain time.Duration) func() {
	previous := observerDrainTimeout
	observerDrainTimeout = drain
	return func() { observerDrainTimeout = previous }
}
