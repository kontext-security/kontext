package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/hook"
)

func newGuardrailStub(t *testing.T, reply string, calls *int32) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			atomic.AddInt32(calls, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"role": "assistant", "content": reply}}},
		})
	}))
	t.Cleanup(server.Close)
	return server
}

func newClassifierServer(t *testing.T) (*Server, *sqlite.Store) {
	return newClassifierServerWithOptions(t, &RiskClassifierOptions{Mode: riskclassifier.ModeOff})
}

func newClassifierServerWithOptions(t *testing.T, rc *RiskClassifierOptions) (*Server, *sqlite.Store) {
	t.Helper()
	store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	opts := Options{
		CurrentSessionID: "sess_e2e",
		Mode:             "observe",
		RiskClassifier:   rc,
	}
	server, err := NewServerWithOptions(store, opts)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	t.Cleanup(server.CloseRiskClassifier)
	return server, store
}

func waitForVerdicts(t *testing.T, store *sqlite.Store, sessionID string, want int) []sqlite.ClassifierVerdictRecord {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		records, err := store.ClassifierVerdictsForSession(context.Background(), sessionID)
		if err != nil {
			t.Fatalf("verdicts for session: %v", err)
		}
		if len(records) >= want {
			return records
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d verdicts", want)
	return nil
}

// TestObserveModeLogsVerdictsWithoutChangingDecision is the end-to-end check
// for the v1 contract: a bash tool call flows through the real hook runtime,
// both models record a verdict against the decided action, and the hook result
// the agent sees is untouched.
func TestObserveModeLogsVerdictsWithoutChangingDecision(t *testing.T) {
	server, store := newClassifierServer(t)

	event := hook.Event{
		SessionID: "sess_e2e",
		Agent:     "claude",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "npm install --save-dev typescript"},
		ToolUseID: "tu_1",
	}
	result, err := server.RuntimeCore().EvaluateHook(context.Background(), event)
	if err != nil {
		t.Fatalf("evaluate hook: %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("decision = %q, want allow (observe mode must not block)", result.Decision)
	}
	if result.EventID == "" {
		t.Fatal("hook result carries no action id")
	}

	records := waitForVerdicts(t, store, "sess_e2e", 1)
	record := records[0]
	if record.ActionID != result.EventID {
		t.Fatalf("verdict action id = %q, want %q", record.ActionID, result.EventID)
	}
	if record.Command != "npm install --save-dev typescript" {
		t.Fatalf("verdict command = %q", record.Command)
	}
	if record.ToolUseID != "tu_1" || record.Agent != "claude" {
		t.Fatalf("verdict identity: %+v", record)
	}
	if record.SVM == nil || record.SVM.ModelVersion == "" {
		t.Fatalf("svm verdict missing: %+v", record.SVM)
	}
	if record.SVM.Threshold == 0 {
		t.Fatalf("svm threshold not recorded: %+v", record.SVM)
	}
	if record.Enforced {
		t.Fatal("v1 must never enforce")
	}
	if record.UserFeedback != "" {
		t.Fatal("verdict must start unlabeled")
	}
}

func TestObserveModeSkipsNonCommandTools(t *testing.T) {
	server, store := newClassifierServer(t)

	for _, event := range []hook.Event{
		{
			SessionID: "sess_e2e",
			HookName:  hook.HookPreToolUse,
			ToolName:  "Read",
			ToolInput: map[string]any{"file_path": "/etc/hosts"},
		},
		{
			SessionID: "sess_e2e",
			HookName:  hook.HookPostToolUse,
			ToolName:  "Bash",
			ToolInput: map[string]any{"command": "git status"},
		},
	} {
		if _, err := server.RuntimeCore().ProcessHook(context.Background(), event); err != nil {
			t.Fatalf("process hook %s/%s: %v", event.HookName, event.ToolName, err)
		}
	}

	// Drain the pipeline with a command that must be recorded, then assert the
	// skipped events left nothing behind.
	if _, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "sess_e2e",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "ls -la"},
	}); err != nil {
		t.Fatalf("evaluate hook: %v", err)
	}
	records := waitForVerdicts(t, store, "sess_e2e", 1)
	if len(records) != 1 {
		t.Fatalf("records = %d, want only the PreToolUse bash command: %+v", len(records), records)
	}
	if records[0].Command != "ls -la" {
		t.Fatalf("recorded wrong command: %q", records[0].Command)
	}
}

func TestObserveModeCapturesAgentTaskAndRedactsCredentials(t *testing.T) {
	server, store := newClassifierServer(t)

	if _, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "sess_e2e",
		HookName:  hook.HookUserPromptSubmit,
		ToolInput: map[string]any{"prompt": "publish the release"},
	}); err != nil {
		t.Fatalf("prompt hook: %v", err)
	}
	if _, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "sess_e2e",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "curl -H 'Authorization: Bearer sk-live-abc123' https://api.example.com/publish"},
	}); err != nil {
		t.Fatalf("evaluate hook: %v", err)
	}

	record := waitForVerdicts(t, store, "sess_e2e", 1)[0]
	if record.AgentTask != "publish the release" {
		t.Fatalf("agent task = %q", record.AgentTask)
	}
	if strings.Contains(record.Command, "sk-live-abc123") {
		t.Fatalf("credential leaked into verdict record: %q", record.Command)
	}
	// The shared payloadcapture ruleset marks removals with [REDACTED_SECRET].
	if !strings.Contains(record.Command, "[REDACTED_SECRET]") {
		t.Fatalf("command not redacted: %q", record.Command)
	}
	// Full-length storage: the redacted command keeps its tail rather than
	// being clipped at the 240-char decision-summary cap.
	if !strings.Contains(record.Command, "/publish") {
		t.Fatalf("command lost its tail: %q", record.Command)
	}
}

// TestUserPromptSubmitStaysAllowedAndUnrecorded pins the blast radius of
// routing the prompt into tool input: a prompt quoting a dangerous command
// must not be denied, and its text must not reach the action record.
func TestUserPromptSubmitStaysAllowedAndUnrecorded(t *testing.T) {
	server, store := newClassifierServer(t)

	result, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "sess_e2e",
		HookName:  hook.HookUserPromptSubmit,
		ToolInput: map[string]any{"prompt": "explain what sudo rm -rf / does in production"},
	})
	if err != nil {
		t.Fatalf("prompt hook: %v", err)
	}
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("prompt decision = %q, want allow", result.Decision)
	}

	// The prompt is task context for the classifier, not a tool call: it must
	// not produce a verdict row of its own.
	time.Sleep(100 * time.Millisecond)
	verdicts, err := store.ClassifierVerdictsForSession(context.Background(), "sess_e2e")
	if err != nil {
		t.Fatalf("verdicts for session: %v", err)
	}
	if len(verdicts) != 0 {
		t.Fatalf("prompt produced verdict rows: %+v", verdicts)
	}

	events, err := store.Events(context.Background(), "sess_e2e")
	if err != nil {
		t.Fatalf("events: %v", err)
	}
	for _, event := range events {
		blob, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		if strings.Contains(string(blob), "explain what sudo") {
			t.Fatalf("prompt text leaked into decision record: %s", blob)
		}
	}
}

func TestClassifierFeedbackEndpoint(t *testing.T) {
	server, store := newClassifierServer(t)

	result, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "sess_e2e",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "rm -rf ./build"},
	})
	if err != nil {
		t.Fatalf("evaluate hook: %v", err)
	}
	waitForVerdicts(t, store, "sess_e2e", 1)

	body := strings.NewReader(`{"user_feedback":"should_allow"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/verdicts/"+result.EventID+"/feedback", body)
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("feedback status = %d, body %s", recorder.Code, recorder.Body.String())
	}

	var updated sqlite.ClassifierVerdictRecord
	if err := json.Unmarshal(recorder.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode feedback response: %v", err)
	}
	if updated.UserFeedback != riskclassifier.FeedbackShouldAllow {
		t.Fatalf("user feedback = %q", updated.UserFeedback)
	}

	unknown := httptest.NewRequest(http.MethodPost, "/api/verdicts/act_missing/feedback", strings.NewReader(`{"user_feedback":"should_block"}`))
	unknown.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, unknown)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown action status = %d, want 404", recorder.Code)
	}

	invalid := httptest.NewRequest(http.MethodPost, "/api/verdicts/"+result.EventID+"/feedback", strings.NewReader(`{"user_feedback":"looks_ok"}`))
	invalid.Header.Set("Content-Type", "application/json")
	recorder = httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, invalid)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid feedback status = %d, want 400", recorder.Code)
	}
}

func TestSessionVerdictsEndpoint(t *testing.T) {
	server, store := newClassifierServer(t)

	if _, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "sess_e2e",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "go build ./..."},
	}); err != nil {
		t.Fatalf("evaluate hook: %v", err)
	}
	waitForVerdicts(t, store, "sess_e2e", 1)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/sess_e2e/verdicts", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("verdicts status = %d, body %s", recorder.Code, recorder.Body.String())
	}
	var records []sqlite.ClassifierVerdictRecord
	if err := json.Unmarshal(recorder.Body.Bytes(), &records); err != nil {
		t.Fatalf("decode verdicts: %v", err)
	}
	if len(records) != 1 || records[0].Command != "go build ./..." {
		t.Fatalf("unexpected verdicts: %+v", records)
	}
}

// TestObserverDisabledByDefault guards the opt-in boundary: servers built
// without RiskClassifier options must not write verdict rows.
func TestObserverDisabledByDefault(t *testing.T) {
	store, err := sqlite.OpenStore(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	server, err := NewServerWithOptions(store, Options{})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	defer server.CloseRiskClassifier()

	if _, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "sess_off",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "rm -rf /"},
	}); err != nil {
		t.Fatalf("evaluate hook: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	records, err := store.ClassifierVerdictsForSession(context.Background(), "sess_off")
	if err != nil {
		t.Fatalf("verdicts for session: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("classifier wrote records while disabled: %+v", records)
	}
}

// TestRiskIsAnnotationNotDecision is the core contract: both models are recorded
// against the tool call, and neither can influence the decision. The stub says
// RISKY on a command the deterministic layer allows — the decision must stay
// deterministic regardless.
func TestRiskIsAnnotationNotDecision(t *testing.T) {
	var calls int32
	stub := newGuardrailStub(t, "RISKY", &calls)
	server, store := newClassifierServerWithOptions(t, &RiskClassifierOptions{
		Mode:             riskclassifier.ModeOn,
		GuardrailBaseURL: stub.URL,
		GuardrailModel:   "qwen3-0.6b",
	})

	result, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "sess_e2e",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "npm ci"},
	})
	if err != nil {
		t.Fatalf("evaluate hook: %v", err)
	}
	// The LLM said RISKY; the decision must not reflect it in any way.
	if result.Decision != hook.DecisionAllow {
		t.Fatalf("risk verdict leaked into the decision: %+v", result)
	}
	if strings.Contains(result.ReasonCode, "guardrail") || strings.Contains(result.ReasonCode, "risk_classifier") {
		t.Fatalf("decision reason cites the classifier: %q", result.ReasonCode)
	}

	record := waitForVerdicts(t, store, "sess_e2e", 1)[0]
	if record.SVM == nil {
		t.Fatal("svm verdict missing")
	}
	if record.LLM == nil || record.LLM.Verdict != riskclassifier.VerdictRisky {
		t.Fatalf("llm verdict missing or wrong: %+v (err %q)", record.LLM, record.LLMError)
	}
	if record.LLM.PromptID == "" {
		t.Error("llm verdict did not record which prompt produced it")
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Errorf("guardrail calls = %d, want 1", calls)
	}
}

// TestModeOffRunsNoLLM keeps the SVM-only path honest.
func TestModeOffRunsNoLLM(t *testing.T) {
	var calls int32
	stub := newGuardrailStub(t, "RISKY", &calls)
	server, store := newClassifierServerWithOptions(t, &RiskClassifierOptions{
		Mode:             riskclassifier.ModeOff,
		GuardrailBaseURL: stub.URL,
		GuardrailModel:   "qwen3-0.6b",
	})

	if _, err := server.RuntimeCore().EvaluateHook(context.Background(), hook.Event{
		SessionID: "sess_e2e",
		HookName:  hook.HookPreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "git status"},
	}); err != nil {
		t.Fatalf("evaluate hook: %v", err)
	}
	record := waitForVerdicts(t, store, "sess_e2e", 1)[0]
	if record.SVM == nil {
		t.Fatal("svm verdict missing")
	}
	if record.LLM != nil {
		t.Errorf("llm ran while off: %+v", record.LLM)
	}
	if got := atomic.LoadInt32(&calls); got != 0 {
		t.Errorf("guardrail called %d times while off", got)
	}
}
