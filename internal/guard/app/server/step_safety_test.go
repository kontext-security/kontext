package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/hookruntime"
	"github.com/kontext-security/kontext/internal/localruntime"
)

type capturingStepSafetyBackend struct {
	mu     sync.Mutex
	inputs []stepsafety.Input
}

func TestAgentPromptAdaptersReachMerlinAndStaySessionLocal(t *testing.T) {
	store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backend := &capturingStepSafetyBackend{}
	evaluator := stepsafety.NewWithBackend(backend, time.Second, 1, stepsafety.ModelVersion)
	defer evaluator.Close()
	server, err := NewServerWithOptions(store, Options{StepSafety: evaluator})
	if err != nil {
		t.Fatal(err)
	}
	decode := func(agent, name, prompt string) hook.Event {
		t.Helper()
		raw, err := json.Marshal(map[string]any{"session_id": "same-id", "hook_event_name": name, "prompt": prompt, "tool_name": "WebSearch", "tool_input": map[string]any{"query": "public release notes"}})
		if err != nil {
			t.Fatal(err)
		}
		var event hook.Event
		if agent == "codex" {
			event, err = hookruntime.DecodeCodexEvent(raw, agent)
		} else {
			event, err = hookruntime.DecodeClaudeEvent(raw, agent)
		}
		if err != nil {
			t.Fatal(err)
		}
		return event
	}
	invoke := func(event hook.Event) {
		t.Helper()
		if _, err := server.RuntimeCore().EvaluateHook(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	invoke(decode("codex", "UserPromptSubmit", "Codex request"))
	invoke(decode("claude_code", "UserPromptSubmit", "Claude request"))
	for _, row := range []struct{ agent, request string }{{"codex", "Codex request"}, {"claude_code", "Claude request"}} {
		invoke(decode(row.agent, "PreToolUse", ""))
		if got := backend.lastInput().UserRequest; got != row.request {
			t.Fatalf("%s request = %q", row.agent, got)
		}
	}
	for _, request := range []string{"New Claude request", ""} {
		invoke(decode("claude_code", "UserPromptSubmit", request))
		invoke(decode("claude_code", "PreToolUse", ""))
		if got := backend.lastInput().UserRequest; got != request {
			t.Fatalf("updated request = %q, want %q", got, request)
		}
	}
	invoke(decode("claude_code", "UserPromptSubmit", "Last request"))
	if err := server.RuntimeCore().CloseSession(context.Background(), "same-id"); err != nil {
		t.Fatal(err)
	}
	invoke(decode("claude_code", "PreToolUse", ""))
	if got := backend.lastInput().UserRequest; got != "" {
		t.Fatalf("closed session leaked %q", got)
	}
}

func TestDeferredStepSafetyUsesPreToolContextAfterHookReturns(t *testing.T) {
	store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backend := &capturingStepSafetyBackend{}
	evaluator := stepsafety.NewWithBackend(backend, time.Second, 1, stepsafety.ModelVersion)
	defer evaluator.Close()
	var jobs []func(context.Context) error
	server, err := NewServerWithOptions(store, Options{
		StepSafety:  evaluator,
		DeferRecord: func(job func(context.Context) error) error { jobs = append(jobs, job); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	core := server.RuntimeCore()
	for _, event := range []hook.Event{
		{SessionID: "snapshot", HookName: hook.HookUserPromptSubmit, ToolInput: map[string]any{"prompt": "Original request"}},
		{SessionID: "snapshot", HookName: hook.HookPostToolUse, ToolName: "get_config", ToolResponse: map[string]any{"value": "prior history"}},
	} {
		var err error
		if event.HookName.CanBlock() {
			_, err = core.EvaluateHook(context.Background(), event)
		} else {
			_, err = core.IngestEvent(context.Background(), event)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	result, err := core.EvaluateHook(ctx, hook.Event{
		SessionID: "snapshot", HookName: hook.HookPreToolUse, ToolName: "update_config",
		ToolInput: map[string]any{"value": "new value"},
	})
	cancel() // A disconnected hook must not cancel its background assessment.
	if err != nil || result.Decision != hook.DecisionAllow || result.EventID == "" {
		t.Fatalf("hook result=%+v, err=%v", result, err)
	}
	if len(backend.inputs) != 0 {
		t.Fatal("Merlin ran before the deferred job, on the hook response path")
	}
	for _, event := range []hook.Event{
		{SessionID: "snapshot", HookName: hook.HookUserPromptSubmit, ToolInput: map[string]any{"prompt": "Later request"}},
		{SessionID: "snapshot", HookName: hook.HookPostToolUse, ToolName: "later_tool"},
		{SessionID: "snapshot", HookName: hook.HookSessionEnd},
	} {
		var err error
		if event.HookName.CanBlock() {
			_, err = core.EvaluateHook(context.Background(), event)
		} else {
			_, err = core.IngestEvent(context.Background(), event)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, job := range jobs {
		if err := job(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	input := backend.lastInput()
	if input.UserRequest != "Original request" || !strings.Contains(input.InteractionHistory, "prior history") || strings.Contains(input.InteractionHistory, "later_tool") {
		t.Fatalf("deferred assessment used context from after the action: %+v", input)
	}
	record, err := store.StepSafetyVerdictForAction(context.Background(), result.EventID)
	if err != nil || record.ShadowDecision != stepsafety.DecisionUnsafe || record.Enforced {
		t.Fatalf("background verdict=%+v, err=%v", record, err)
	}
	if record.ReviewContext == nil || record.ReviewContext.UserRequest != "Original request" {
		t.Fatalf("review context lost its action-time snapshot: %+v", record.ReviewContext)
	}
}

type blockedStepSafetyBackend struct {
	capturingStepSafetyBackend
	started chan struct{}
	release chan struct{}
}

func (b *blockedStepSafetyBackend) Infer(ctx context.Context, input stepsafety.Input) (stepsafety.InferenceResult, error) {
	close(b.started)
	<-b.release
	return b.capturingStepSafetyBackend.Infer(ctx, input)
}

func TestDeferredStepSafetyDoesNotHoldSocketResponse(t *testing.T) {
	store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backend := &blockedStepSafetyBackend{started: make(chan struct{}), release: make(chan struct{})}
	evaluator := stepsafety.NewWithBackend(backend, 5*time.Second, 1, stepsafety.ModelVersion)
	defer evaluator.Close()
	recorder := NewDeferredRecorder(diagnostic.New(io.Discard, false))
	defer recorder.Drain(context.Background())
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(backend.release) })
	server, err := NewServerWithOptions(store, Options{StepSafety: evaluator, DeferRecord: recorder.Submit})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/tmp", "merlin-async-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	service, err := localruntime.NewService(localruntime.Options{SocketPath: filepath.Join(dir, "guard.sock"), Core: server.RuntimeCore(), AgentName: "claude"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer service.Stop()
	client := localruntime.NewClient(service.SocketPath())
	client.Timeout = time.Second
	result, err := client.Process(context.Background(), hook.Event{
		SessionID: "nonblocking", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolInput: map[string]any{"command": "pwd"},
	})
	if err != nil || result.Decision != hook.DecisionAllow {
		t.Fatalf("hook waited on blocked inference: result=%+v, err=%v", result, err)
	}
	select {
	case <-backend.started:
	case <-time.After(time.Second):
		t.Fatal("background inference did not start")
	}
	releaseOnce.Do(func() { close(backend.release) })
	if err := recorder.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	record, err := store.StepSafetyVerdictForAction(context.Background(), result.EventID)
	if err != nil || record.ShadowDecision != stepsafety.DecisionUnsafe || record.Enforced {
		t.Fatalf("background verdict=%+v, err=%v", record, err)
	}
}

func TestStepSafetyAsyncHistoryIsObservedOnceBeforeNextSocketHook(t *testing.T) {
	store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	backend := &capturingStepSafetyBackend{}
	evaluator := stepsafety.NewWithBackend(backend, time.Second, 1, stepsafety.ModelVersion)
	server, err := NewServerWithOptions(store, Options{StepSafety: evaluator})
	if err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp("/tmp", "kontext-step-safety-*")
	if err != nil {
		t.Fatal(err)
	}
	service, err := localruntime.NewService(localruntime.Options{
		SocketPath:  filepath.Join(socketDir, "kontext.sock"),
		Core:        server.RuntimeCore(),
		AgentName:   "claude",
		AsyncIngest: true,
		Diagnostic:  diagnostic.New(io.Discard, false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		service.Stop()
		_ = store.Close()
		_ = os.RemoveAll(socketDir)
	})
	client := localruntime.NewClient(service.SocketPath())

	if _, err := client.Process(context.Background(), hook.Event{
		SessionID: "ordered-step-session",
		HookName:  hook.HookPostToolUse,
		ToolName:  "get_config",
		ToolInput: map[string]any{"file_path": "config.json"},
	}); err != nil {
		t.Fatalf("PostToolUse: %v", err)
	}
	if _, err := client.Process(context.Background(), hook.Event{
		SessionID: "ordered-step-session",
		HookName:  hook.HookPreToolUse,
		ToolName:  "update_config",
		ToolInput: map[string]any{"file_path": "config.json"},
	}); err != nil {
		t.Fatalf("PreToolUse: %v", err)
	}

	history := backend.lastInput().InteractionHistory
	if strings.Count(history, `"tool":"get_config"`) != 1 {
		t.Fatalf("history = %s, want immediately preceding interaction exactly once", history)
	}
}

func (b *capturingStepSafetyBackend) Infer(_ context.Context, input stepsafety.Input) (stepsafety.InferenceResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inputs = append(b.inputs, input)
	// Keep this deliberately unsafe after the matched-replay calibration so
	// these transport tests exercise asynchronous review-context persistence.
	return stepsafety.InferenceResult{Logits: [2]float64{-4, 4}, HistoryOmitted: input.HistoryOmitted}, nil
}

func (b *capturingStepSafetyBackend) Health(context.Context) (stepsafety.Health, error) {
	return stepsafety.Health{Status: "ready", ModelVersion: stepsafety.ModelVersion, Device: "cpu"}, nil
}

func (b *capturingStepSafetyBackend) Close() error { return nil }

func (b *capturingStepSafetyBackend) lastInput() stepsafety.Input {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.inputs[len(b.inputs)-1]
}

// TestStepSafetyRunsAtPreExecutionHook exercises the actual RuntimeCore
// PreToolUse boundary: prompt and structured prior-tool context flow into the
// model, an unsafe shadow score is returned and persisted, and the real policy
// allow remains unchanged.
func TestStepSafetyRunsAtPreExecutionHook(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backend := &capturingStepSafetyBackend{}
	evaluator := stepsafety.NewWithBackend(backend, time.Second, 1, stepsafety.ModelVersion)
	server, err := NewServerWithOptions(store, Options{StepSafety: evaluator})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "step-session",
		HookName:  hook.HookUserPromptSubmit,
		ToolInput: map[string]any{"prompt": "Update the application configuration."},
	}); err != nil {
		t.Fatalf("record user request: %v", err)
	}
	if _, err := server.RuntimeCore().IngestEvent(context.Background(), hook.Event{
		SessionID:    "step-session",
		HookName:     hook.HookPostToolUse,
		ToolName:     "get_config",
		ToolInput:    map[string]any{"file_path": "config.json"},
		ToolResponse: map[string]any{"content": "{}"},
	}); err != nil {
		t.Fatalf("record interaction history: %v", err)
	}

	result, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "step-session",
		HookName:  hook.HookPreToolUse,
		ToolName:  "update_config",
		ToolInput: map[string]any{
			"file_path": "config.json",
			"content":   `{"enabled":true,"token":"secret argument must not persist"}`,
		},
		AvailableToolSchemas: []any{
			map[string]any{"name": "update_config", "input_schema": map[string]any{"type": "object"}},
		},
	})
	if err != nil {
		t.Fatalf("pre-execution evaluation: %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("real decision = %q, want allow despite unsafe shadow result", result.Decision)
	}
	decision, ok := result.Metadata().(risk.RiskDecision)
	if !ok || decision.StepSafety == nil || decision.StepSafety.ShadowDecision != stepsafety.DecisionUnsafe {
		t.Fatalf("step-safety metadata = %+v", decision.StepSafety)
	}
	if decision.StepSafety.Enforced {
		t.Fatal("step-safety result became enforcement authority")
	}
	hostedShape, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(hostedShape), "step_safety") || strings.Contains(string(hostedShape), "unsafe_probability") {
		t.Fatalf("local step-safety evidence leaked into decision JSON: %s", hostedShape)
	}

	input := backend.lastInput()
	if input.UserRequest != "Update the application configuration." || input.ToolName != "update_config" {
		t.Fatalf("model input = %+v", input)
	}
	if !strings.Contains(input.InteractionHistory, `"tool":"get_config"`) ||
		!strings.Contains(input.InteractionHistory, `"observation":"{\"content\":\"{}\"}"`) {
		t.Fatalf("structured history missing prior tool: %s", input.InteractionHistory)
	}
	if len(input.AvailableToolSchemas.([]any)) != 1 {
		t.Fatalf("available schemas = %#v", input.AvailableToolSchemas)
	}

	records, err := store.StepSafetyVerdictsForSession(context.Background(), "step-session")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].UnsafeProbability == nil || records[0].ShadowDecision != stepsafety.DecisionUnsafe {
		t.Fatalf("stored step-safety telemetry = %+v", records)
	}
	if records[0].ToolName != "update_config" || records[0].Enforced {
		t.Fatalf("stored redacted telemetry = %+v", records[0])
	}
	if !records[0].UserRequestPresent || !records[0].HistoryPresent || !records[0].ToolSchemasPresent {
		t.Fatalf("context coverage telemetry = %+v", records[0])
	}
	if records[0].ReviewContext == nil || records[0].ReviewContext.UserRequest != input.UserRequest || !strings.Contains(records[0].ReviewContext.InteractionHistory, "get_config") {
		t.Fatalf("review context did not preserve the assessed action snapshot: %+v", records[0].ReviewContext)
	}

	feedback := httptest.NewRequest(http.MethodPost, "/api/step-safety/"+result.EventID+"/feedback", strings.NewReader(`{"user_feedback":"should_allow"}`))
	feedback.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, feedback)
	if recorder.Code != http.StatusOK {
		t.Fatalf("feedback status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var reviewed sqlite.StepSafetyRecord
	if err := json.Unmarshal(recorder.Body.Bytes(), &reviewed); err != nil {
		t.Fatal(err)
	}
	if reviewed.UserFeedback != riskclassifier.FeedbackShouldAllow || reviewed.FeedbackAt == nil {
		t.Fatalf("reviewed record = %+v", reviewed)
	}
}

func TestStepSafetyExcludedFileToolsStayUnscored(t *testing.T) {
	store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backend := &capturingStepSafetyBackend{}
	evaluator := stepsafety.NewWithBackend(backend, time.Second, 1, stepsafety.ModelVersion)
	server, err := NewServerWithOptions(store, Options{StepSafety: evaluator})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Read", "Write", "Edit"} {
		result, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{SessionID: "excluded", HookName: hook.HookPreToolUse, ToolName: name, ToolInput: map[string]any{"file_path": "config.json", "content": strings.Repeat("large file content", 1000)}})
		if err != nil {
			t.Fatal(err)
		}
		decision, ok := result.Metadata().(risk.RiskDecision)
		if !ok || decision.StepSafety == nil || decision.StepSafety.ErrorCode != stepsafety.ErrorExcludedTool || decision.StepSafety.UnsafeProbability != nil || decision.StepSafety.Enforced {
			t.Fatalf("excluded tool metadata=%+v", decision.StepSafety)
		}
		if result.Decision != hook.DecisionAllow {
			t.Fatalf("excluded file tool changed settled policy: %s", result.Decision)
		}
	}
	backend.mu.Lock()
	calls := len(backend.inputs)
	backend.mu.Unlock()
	if calls != 0 {
		t.Fatalf("file tools called inference %d times", calls)
	}
	records, err := store.StepSafetyVerdictsForSession(context.Background(), "excluded")
	if err != nil || len(records) != 3 {
		t.Fatalf("exclusion records=%+v, err=%v", records, err)
	}
	for _, record := range records {
		if record.UnsafeProbability != nil || record.ErrorCode != stepsafety.ErrorExcludedTool {
			t.Fatalf("excluded call was scored: %+v", record)
		}
	}
}
