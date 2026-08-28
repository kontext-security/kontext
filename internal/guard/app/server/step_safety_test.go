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
	"github.com/kontext-security/kontext/internal/localruntime"
)

type capturingStepSafetyBackend struct {
	mu     sync.Mutex
	inputs []stepsafety.Input
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
		ToolName:  "Read",
		ToolInput: map[string]any{"file_path": "config.json"},
	}); err != nil {
		t.Fatalf("PostToolUse: %v", err)
	}
	if _, err := client.Process(context.Background(), hook.Event{
		SessionID: "ordered-step-session",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Write",
		ToolInput: map[string]any{"file_path": "config.json"},
	}); err != nil {
		t.Fatalf("PreToolUse: %v", err)
	}

	history := backend.lastInput().InteractionHistory
	if strings.Count(history, `"tool_name":"Read"`) != 1 {
		t.Fatalf("history = %s, want immediately preceding interaction exactly once", history)
	}
}

func (b *capturingStepSafetyBackend) Infer(_ context.Context, input stepsafety.Input) ([2]float64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.inputs = append(b.inputs, input)
	return [2]float64{-1, 1}, nil
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
		ToolName:     "Read",
		ToolInput:    map[string]any{"file_path": "config.json"},
		ToolResponse: map[string]any{"content": "{}"},
	}); err != nil {
		t.Fatalf("record interaction history: %v", err)
	}

	result, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "step-session",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Write",
		ToolInput: map[string]any{
			"file_path": "config.json",
			"content":   `{"enabled":true,"token":"secret argument must not persist"}`,
		},
		AvailableToolSchemas: []any{
			map[string]any{"name": "Write", "input_schema": map[string]any{"type": "object"}},
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
	if input.UserRequest != "Update the application configuration." || input.ToolName != "Write" {
		t.Fatalf("model input = %+v", input)
	}
	if !strings.Contains(input.InteractionHistory, `"tool_name":"Read"`) {
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
	if records[0].ToolName != "Write" || records[0].Enforced {
		t.Fatalf("stored redacted telemetry = %+v", records[0])
	}
	if !records[0].UserRequestPresent || !records[0].HistoryPresent || !records[0].ToolSchemasPresent {
		t.Fatalf("context coverage telemetry = %+v", records[0])
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
