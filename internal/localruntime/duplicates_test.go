package localruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
)

// Codex runs every hooks.json handler for an event at once, so a Kontext hook
// named in two files reaches the daemon twice, concurrently.
func TestServiceEvaluatesConcurrentDuplicatePreToolUseOnce(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	runtime := &stubRuntime{
		evaluate: func(call int32, _ hook.Event) (hook.Result, error) {
			if call == 1 {
				close(started)
				<-release
			}
			return hook.Result{Decision: hook.DecisionDeny, Reason: "blocked by runtime", EventID: fmt.Sprintf("act_%d", call)}, nil
		},
	}
	service := newTestService(t, runtime, true)
	t.Cleanup(unblock) // Release before the service cleanup waits for handlers.
	client := NewClient(service.SocketPath())
	event := codexToolEvent(hook.HookPreToolUse, "call_1")

	results := make(chan hook.Result, 2)
	errs := make(chan error, 2)
	process := func() {
		result, err := client.Process(context.Background(), event)
		if err != nil {
			errs <- err
			return
		}
		results <- result
	}
	go process()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first copy was not evaluated")
	}
	go process()
	// Let the copy reach the unsettled first. One that arrives after it settled
	// must get the same answer from the settled result.
	time.Sleep(50 * time.Millisecond)
	unblock()

	for range 2 {
		select {
		case err := <-errs:
			t.Fatalf("Process() error = %v", err)
		case result := <-results:
			if result.Decision != hook.DecisionDeny || result.Reason != "blocked by runtime" || result.EventID != "act_1" {
				t.Fatalf("Process() = %+v, want the first evaluation's deny", result)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("a copy was not answered")
		}
	}
	if got := runtime.evaluateCalls.Load(); got != 1 {
		t.Fatalf("EvaluateHook calls = %d, want 1", got)
	}
}

func TestServiceIngestsDuplicatePostToolUseOnce(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{}
	service := newTestService(t, runtime, true)
	client := NewClient(service.SocketPath())
	event := codexToolEvent(hook.HookPostToolUse, "call_1")

	for range 2 {
		result, err := client.Process(context.Background(), event)
		if err != nil {
			t.Fatalf("Process() error = %v", err)
		}
		if result.Decision != hook.DecisionAllow {
			t.Fatalf("Process().Decision = %q, want allow", result.Decision)
		}
	}
	shutdown(t, service)
	if got := runtime.observeCalls.Load(); got != 1 {
		t.Fatalf("ObserveAsyncEvent calls = %d, want 1", got)
	}
	if got := runtime.ingestCalls.Load(); got != 1 {
		t.Fatalf("IngestEvent calls = %d, want 1", got)
	}
}

func TestServiceProcessesDistinctToolCalls(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{evaluateResult: hook.Result{Decision: hook.DecisionAllow}}
	service := newTestService(t, runtime, true)
	client := NewClient(service.SocketPath())

	// Same tool, same input, two calls.
	for _, id := range []string{"call_1", "call_2"} {
		for _, name := range []hook.HookName{hook.HookPreToolUse, hook.HookPostToolUse} {
			if _, err := client.Process(context.Background(), codexToolEvent(name, id)); err != nil {
				t.Fatalf("Process(%s %s) error = %v", name, id, err)
			}
		}
	}
	shutdown(t, service)
	if got := runtime.evaluateCalls.Load(); got != 2 {
		t.Fatalf("EvaluateHook calls = %d, want 2", got)
	}
	if got := runtime.ingestCalls.Load(); got != 2 {
		t.Fatalf("IngestEvent calls = %d, want 2", got)
	}
}

func TestServiceProcessesSameEventAgainAfterWindow(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{evaluateResult: hook.Result{Decision: hook.DecisionAllow}}
	service := newTestService(t, runtime, true)
	clock := &testClock{now: time.Now()}
	service.duplicates.mu.Lock()
	service.duplicates.now = clock.Now
	service.duplicates.mu.Unlock()
	client := NewClient(service.SocketPath())
	send := func() {
		t.Helper()
		for _, name := range []hook.HookName{hook.HookPreToolUse, hook.HookPostToolUse} {
			if _, err := client.Process(context.Background(), codexToolEvent(name, "call_1")); err != nil {
				t.Fatalf("Process(%s) error = %v", name, err)
			}
		}
	}

	send()
	clock.advance(duplicateHookWindow - time.Millisecond)
	send()
	if got := runtime.evaluateCalls.Load(); got != 1 {
		t.Fatalf("EvaluateHook calls inside the window = %d, want 1", got)
	}
	clock.advance(time.Millisecond)
	send()
	shutdown(t, service)
	if got := runtime.evaluateCalls.Load(); got != 2 {
		t.Fatalf("EvaluateHook calls = %d, want 2", got)
	}
	if got := runtime.ingestCalls.Load(); got != 2 {
		t.Fatalf("IngestEvent calls = %d, want 2", got)
	}
}

// A prompt carries no tool call id, so its copies are recognized by content.
func TestServiceEvaluatesPromptCopiesOnce(t *testing.T) {
	t.Parallel()

	runtime := &stubRuntime{evaluateResult: hook.Result{Decision: hook.DecisionAllow}}
	service := newTestService(t, runtime, true)
	client := NewClient(service.SocketPath())
	prompt := func(session, text string) hook.Event {
		return hook.Event{
			SessionID: session,
			Agent:     "codex",
			HookName:  hook.HookUserPromptSubmit,
			ToolInput: map[string]any{"prompt": text},
		}
	}

	for _, event := range []hook.Event{
		prompt("codex-a", "fix the build"),
		prompt("codex-a", "fix the build"),
		prompt("codex-a", "now run the tests"),
		prompt("codex-b", "fix the build"),
	} {
		if _, err := client.Process(context.Background(), event); err != nil {
			t.Fatalf("Process() error = %v", err)
		}
	}
	if got := runtime.evaluateCalls.Load(); got != 3 {
		t.Fatalf("EvaluateHook calls = %d, want 3", got)
	}
}

// A failed evaluation is never shared: the copy evaluates on its own.
func TestServiceEvaluatesCopyWhenFirstFails(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	runtime := &stubRuntime{
		evaluate: func(call int32, _ hook.Event) (hook.Result, error) {
			if call == 1 {
				close(started)
				<-release
				return hook.Result{}, errors.New("policy unavailable")
			}
			return hook.Result{Decision: hook.DecisionAllow, Reason: "evaluated alone"}, nil
		},
	}
	service := newTestService(t, runtime, true)
	t.Cleanup(unblock)
	client := NewClient(service.SocketPath())
	event := codexToolEvent(hook.HookPreToolUse, "call_1")

	first := make(chan hook.Result, 1)
	go func() {
		result, _ := client.Process(context.Background(), event)
		first <- result
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first copy was not evaluated")
	}
	copied := make(chan hook.Result, 1)
	go func() {
		result, _ := client.Process(context.Background(), event)
		copied <- result
	}()
	time.Sleep(50 * time.Millisecond)
	unblock()

	if result := <-first; result.Decision != hook.DecisionDeny || result.Reason != "Kontext access policy could not be evaluated." {
		t.Fatalf("first Process() = %+v, want the evaluation failure", result)
	}
	if result := <-copied; result.Decision != hook.DecisionAllow || result.Reason != "evaluated alone" {
		t.Fatalf("copy Process() = %+v, want its own evaluation", result)
	}
	if got := runtime.evaluateCalls.Load(); got != 2 {
		t.Fatalf("EvaluateHook calls = %d, want 2", got)
	}
}

// A copy never waits on a stuck first copy longer than the window.
func TestServiceEvaluatesCopyWhenFirstHangs(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	runtime := &stubRuntime{
		evaluate: func(call int32, _ hook.Event) (hook.Result, error) {
			if call == 1 {
				close(started)
				<-release
			}
			return hook.Result{Decision: hook.DecisionAllow, Reason: fmt.Sprintf("evaluation %d", call)}, nil
		},
	}
	service := newTestService(t, runtime, true)
	t.Cleanup(unblock)
	service.duplicates.mu.Lock()
	service.duplicates.window = 50 * time.Millisecond
	service.duplicates.mu.Unlock()
	client := NewClient(service.SocketPath())
	event := codexToolEvent(hook.HookPreToolUse, "call_1")

	first := make(chan hook.Result, 1)
	go func() {
		result, _ := client.Process(context.Background(), event)
		first <- result
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("first copy was not evaluated")
	}
	result, err := client.Process(context.Background(), event)
	if err != nil {
		t.Fatalf("copy Process() error = %v", err)
	}
	if result.Reason != "evaluation 2" {
		t.Fatalf("copy Process() = %+v, want its own evaluation", result)
	}
	unblock()
	if result := <-first; result.Reason != "evaluation 1" {
		t.Fatalf("first Process() = %+v, want its own evaluation", result)
	}
}

func TestDuplicateHooksForgetEventsPastWindow(t *testing.T) {
	t.Parallel()

	clock := &testClock{now: time.Now()}
	duplicates := newDuplicateHooks()
	duplicates.now = clock.Now
	for i := range 100 {
		duplicates.do(codexToolEvent(hook.HookPostToolUse, fmt.Sprintf("call_%d", i)), &EvaluateRequest{}, allowHook)
	}
	if got := len(duplicates.events); got != 100 {
		t.Fatalf("tracked events = %d, want 100", got)
	}
	clock.advance(duplicateHookWindow)
	duplicates.do(codexToolEvent(hook.HookPostToolUse, "call_next"), &EvaluateRequest{}, allowHook)
	if got := len(duplicates.events); got != 1 {
		t.Fatalf("tracked events after the window = %d, want 1", got)
	}
}

func TestDuplicateHooksProcessUntrackedWhenFull(t *testing.T) {
	t.Parallel()

	duplicates := newDuplicateHooks()
	duplicates.now = (&testClock{now: time.Now()}).Now
	for i := range maxTrackedHookEvents {
		duplicates.do(codexToolEvent(hook.HookPostToolUse, fmt.Sprintf("call_%d", i)), &EvaluateRequest{}, allowHook)
	}
	overflow := codexToolEvent(hook.HookPostToolUse, "call_overflow")
	for range 2 {
		if _, duplicate, _ := duplicates.do(overflow, &EvaluateRequest{}, allowHook); duplicate {
			t.Fatal("an untracked event was answered as a duplicate")
		}
	}
	if got := len(duplicates.events); got != maxTrackedHookEvents {
		t.Fatalf("tracked events = %d, want %d", got, maxTrackedHookEvents)
	}
}

func TestDuplicateHooksForgetPanickedFirstCopy(t *testing.T) {
	t.Parallel()

	duplicates := newDuplicateHooks()
	event := codexToolEvent(hook.HookPreToolUse, "call_1")
	func() {
		defer func() { _ = recover() }()
		duplicates.do(event, &EvaluateRequest{}, func() (hook.Result, error) { panic("evaluation panicked") })
	}()
	result, duplicate, err := duplicates.do(event, &EvaluateRequest{}, allowHook)
	if err != nil || duplicate || result.Decision != hook.DecisionAllow {
		t.Fatalf("do() = %+v, %v, %v; want its own evaluation", result, duplicate, err)
	}
}

func TestHookEventKey(t *testing.T) {
	t.Parallel()

	key := func(event hook.Event) hookKey {
		t.Helper()
		req, err := EvaluateRequestFromEvent(event)
		if err != nil {
			t.Fatalf("EvaluateRequestFromEvent() error = %v", err)
		}
		key, ok := hookEventKey(event, &req)
		if !ok {
			t.Fatal("hookEventKey() did not key the event")
		}
		return key
	}
	call := codexToolEvent(hook.HookPreToolUse, "call_1")
	// A copy from an older Kontext build may decode the same call with fewer
	// fields; the tool call id still names it.
	olderCall := call
	olderCall.ToolInput = nil
	prompt := hook.Event{SessionID: "codex-a", Agent: "codex", HookName: hook.HookUserPromptSubmit, ToolInput: map[string]any{"prompt": "fix the build"}}
	otherPrompt := prompt
	otherPrompt.ToolInput = map[string]any{"prompt": "now run the tests"}
	otherCall := call
	otherCall.ToolUseID = "call_2"
	failed := call
	failed.HookName = hook.HookPostToolUseFailed
	otherSession := call
	otherSession.SessionID = "codex-b"
	otherAgent := call
	otherAgent.Agent = "claude"
	shifted := hook.Event{Agent: "ab", SessionID: "c", HookName: hook.HookStop}
	shiftedBack := hook.Event{Agent: "a", SessionID: "bc", HookName: hook.HookStop}

	for _, tc := range []struct {
		name string
		a, b hook.Event
		same bool
	}{
		{"tool call copy", call, call, true},
		{"tool call copy from an older build", call, olderCall, true},
		{"prompt copy", prompt, prompt, true},
		{"another prompt", prompt, otherPrompt, false},
		{"another tool call", call, otherCall, false},
		{"another hook", call, failed, false},
		{"another session", call, otherSession, false},
		{"another agent", call, otherAgent, false},
		{"fields shifted across a boundary", shifted, shiftedBack, false},
	} {
		if got := key(tc.a) == key(tc.b); got != tc.same {
			t.Errorf("%s: same key = %v, want %v", tc.name, got, tc.same)
		}
	}
}

func codexToolEvent(name hook.HookName, toolUseID string) hook.Event {
	return hook.Event{
		SessionID: "codex-session",
		Agent:     "codex",
		HookName:  name,
		ToolName:  "Bash",
		ToolUseID: toolUseID,
		ToolInput: map[string]any{"command": "go test ./..."},
	}
}

func allowHook() (hook.Result, error) {
	return hook.Result{Decision: hook.DecisionAllow}, nil
}

// shutdown drains the service, post-response ingestion included.
func shutdown(t *testing.T, service *Service) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := service.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
