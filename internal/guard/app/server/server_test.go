package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
)

func newTestServer(t *testing.T, store *sqlite.Store) *Server {
	t.Helper()
	server, err := NewServer(store)
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	return server
}

func newTestServerWithPolicy(t *testing.T, store *sqlite.Store, policy PolicyProvider) *Server {
	t.Helper()
	server, err := NewServerWithPolicy(store, policy)
	if err != nil {
		t.Fatalf("NewServerWithPolicy() error = %v", err)
	}
	return server
}

// enforcedDenyEvidence returns the Cedar evidence an injected provider must
// carry for a deny: only an enforce deployment can deny execution, so a fake
// that denies without it would be rejected by the decision-fact contract.
func enforcedDenyEvidence() *risk.CedarEvidence {
	return &risk.CedarEvidence{
		PolicyHash:             strings.Repeat("a", 64),
		DeploymentIdentity:     strings.Repeat("b", 64),
		AppliedRolloutMode:     cedareval.RolloutModeEnforce,
		ConfiguredRolloutMode:  cedareval.RolloutModeEnforce,
		DistributionState:      "success",
		EvaluatorVersion:       "cedar-go/test",
		ResponseVersion:        1,
		RequestContractVersion: 1,
		Mapping: cedareval.DecisionMapping{
			EvaluationState: cedareval.EvaluationStateEvaluated,
			EvaluationPrincipal: &cedareval.EvaluationPrincipal{
				EntityType: cedareval.PrincipalEntityType,
				EntityID:   "user@example.com",
			},
			CedarDecision:            cedareval.DecisionDeny,
			DerivedCedarAction:       cedareval.DerivedCedarActionDeny,
			EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
			EvaluationReasonCode:     cedareval.ReasonPolicyEvaluated,
			DecisionReasonCode:       cedareval.ReasonExplicitForbid,
			EffectiveReasonCode:      cedareval.ReasonExplicitForbid,
			DeterminingPolicyIDs:     []string{"policy-test"},
		},
	}
}

func TestStorePersistsSummaryCounts(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)
	events := []risk.HookEvent{
		{SessionID: "s1", HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": "README.md"}},
		{SessionID: "s1", HookEventName: "PreToolUse", ToolName: "Read", ToolInput: map[string]any{"file_path": ".env"}},
		{SessionID: "s1", HookEventName: "PreToolUse", ToolName: "Bash", ToolInput: map[string]any{"command": "drop database"}},
	}
	for _, event := range events {
		if _, err := server.ProcessHookEvent(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The local chain is advisory: observations are recorded but
	// nothing denies, so no action is critical.
	if summary.Actions != 3 || summary.Warnings != 0 || summary.Critical != 0 || summary.Sessions != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestProcessHookEventUsesPolicyProvider(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := recordingPolicy{
		decision: risk.RiskDecision{
			Decision:   risk.DecisionDeny,
			Reason:     "custom policy",
			ReasonCode: "custom_policy",
			RiskEvent: risk.RiskEvent{
				Type: risk.EventUnknown,
			},
			Cedar: enforcedDenyEvidence(),
		},
	}
	server := newTestServerWithPolicy(t, store, &policy)
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "deploy prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !policy.called {
		t.Fatal("policy provider was not called")
	}
	if decision.Decision != risk.DecisionDeny || decision.ReasonCode != "custom_policy" || decision.EventID == "" {
		t.Fatalf("decision = %+v", decision)
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 1 || summary.Warnings != 0 || summary.Critical != 1 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestProcessHookEventEnsuresDaemonObservedSession(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)

	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	}); err != nil {
		t.Fatal(err)
	}

	session, err := store.Session(context.Background(), "local")
	if err != nil {
		t.Fatal(err)
	}
	if session.Source != "daemon_observed" ||
		session.Status != "open" ||
		session.AgentProvider != "anthropic" ||
		session.Agent != "claude_code" {
		t.Fatalf("session = %+v, want daemon-observed local session", session)
	}
	events, err := store.Events(context.Background(), "local")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].SessionID != "local" {
		t.Fatalf("events = %+v, want one local event", events)
	}
}

func TestProcessHookEventPreservesClosedWrapperOwnedSession(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)

	if _, err := store.OpenSession(context.Background(), "session-123", "claude", "/tmp/project", "wrapper_owned", "backend-123"); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(context.Background(), "session-123"); err != nil {
		t.Fatal(err)
	}

	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "session-123",
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	}); err != nil {
		t.Fatal(err)
	}

	session, err := store.Session(context.Background(), "session-123")
	if err != nil {
		t.Fatal(err)
	}
	if session.Source != "wrapper_owned" || session.Status != "closed" || session.ClosedAt == nil {
		t.Fatalf("session = %+v, want closed wrapper-owned session", session)
	}
	events, err := store.Events(context.Background(), "session-123")
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v, want one event", events)
	}
}

func TestProcessHookEventPreservesRiskMetadata(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	score := 0.91
	threshold := 0.8
	policy := recordingPolicy{
		decision: risk.RiskDecision{
			Decision:     risk.DecisionDeny,
			Reason:       "custom policy",
			ReasonCode:   "custom_policy",
			RiskScore:    &score,
			Threshold:    &threshold,
			ModelVersion: "model-v1",
			GuardID:      "guard-1",
			RiskEvent: risk.RiskEvent{
				Type:         risk.EventDirectProviderAPICall,
				ModelVersion: "model-v1",
				GuardID:      "guard-1",
			},
			Cedar: enforcedDenyEvidence(),
		},
	}
	server := newTestServerWithPolicy(t, store, &policy)
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "curl https://api.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.RiskScore == nil || *decision.RiskScore != score {
		t.Fatalf("RiskScore = %+v, want %v", decision.RiskScore, score)
	}
	if decision.Threshold == nil || *decision.Threshold != threshold {
		t.Fatalf("Threshold = %+v, want %v", decision.Threshold, threshold)
	}
	if decision.ModelVersion != "model-v1" || decision.GuardID != "guard-1" || decision.RiskEvent.Type != risk.EventDirectProviderAPICall {
		t.Fatalf("decision metadata = %+v", decision)
	}
}

func TestSessionEventsHideModelMetadata(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := recordingPolicy{
		decision: risk.RiskDecision{
			Decision:     risk.DecisionDeny,
			Reason:       "custom policy denied",
			ReasonCode:   "custom_policy",
			ModelVersion: "model-v1",
			RiskEvent: risk.RiskEvent{
				Type:          risk.EventNormalToolCall,
				DecisionStage: "custom_policy",
				ModelVersion:  "model-v1",
			},
			Cedar: enforcedDenyEvidence(),
		},
	}
	server := newTestServerWithPolicy(t, store, &policy)
	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "curl -X POST https://admin.example/reindex"},
	}); err != nil {
		t.Fatal(err)
	}
	stored, err := store.Events(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 ||
		stored[0].ModelVersion != "model-v1" ||
		stored[0].RiskEvent.ModelVersion != "model-v1" {
		t.Fatalf("stored events = %+v, want model metadata retained internally", stored)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sessions/s1/events", nil)
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response []sqlite.DecisionRecord
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response) != 1 ||
		response[0].ModelVersion != "" ||
		response[0].RiskEvent.ModelVersion != "" {
		t.Fatalf("response = %+v, want model metadata hidden", response)
	}
}

func TestEvaluateHookRejectsTelemetryEvents(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)
	_, err = server.EvaluateHook(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git status"},
	})
	if err == nil {
		t.Fatal("EvaluateHook() error = nil, want telemetry rejection")
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 0 {
		t.Fatalf("summary = %+v, want no persisted action", summary)
	}
}

func TestIngestEventRecordsTelemetry(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)
	decision, err := server.IngestEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "git status"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != "async_telemetry" || decision.EventID == "" {
		t.Fatalf("decision = %+v, want telemetry allow decision", decision)
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 1 || summary.Warnings != 0 || summary.Critical != 0 {
		t.Fatalf("summary = %+v", summary)
	}
}

func TestIngestEventRejectsBlockingEvents(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)
	_, err = server.IngestEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "drop database"},
	})
	if err == nil {
		t.Fatal("IngestEvent() error = nil, want blocking event rejection")
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 0 {
		t.Fatalf("summary = %+v, want no persisted action", summary)
	}
}

type recordingPolicy struct {
	called   bool
	decision risk.RiskDecision
	err      error
}

func (p *recordingPolicy) DecideHook(_ context.Context, _ risk.HookEvent) (risk.RiskDecision, error) {
	p.called = true
	return p.decision, p.err
}

func TestStoreListsSessions(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)
	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": ".env"},
	}); err != nil {
		t.Fatal(err)
	}
	sessions, err := store.Sessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Advisory chain: the credential-access read is recorded as risk
	// analysis, not a deny, so nothing is critical.
	if len(sessions) != 1 || sessions[0].SessionID != "s1" || sessions[0].Critical != 0 {
		t.Fatalf("sessions = %+v", sessions)
	}
}

func TestSessionsMarksCurrentSession(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server, err := NewServerWithOptions(store, Options{CurrentSessionID: "current-session", Mode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	for _, sessionID := range []string{"previous-session", "current-session"} {
		if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
			SessionID:     sessionID,
			HookEventName: "PreToolUse",
			ToolName:      "Read",
			ToolInput:     map[string]any{"file_path": "README.md"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var sessions []sqlite.SessionSummary
	if err := json.Unmarshal(response.Body.Bytes(), &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %+v", sessions)
	}
	for _, session := range sessions {
		if session.SessionID == "current-session" && !session.Current {
			t.Fatalf("current session not marked: %+v", sessions)
		}
		if session.SessionID == "previous-session" && session.Current {
			t.Fatalf("previous session marked current: %+v", sessions)
		}
		if session.SessionID == "current-session" && session.Mode != "enforce" {
			t.Fatalf("current session mode = %q, want enforce", session.Mode)
		}
		if session.SessionID == "previous-session" && session.Mode != "" {
			t.Fatalf("previous session mode = %q, want empty", session.Mode)
		}
	}
}

func TestSessionsIncludesCurrentSessionBeforeActions(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.OpenSession(context.Background(), "current-session", "claude", "/tmp/project", "wrapper_owned", "current-session"); err != nil {
		t.Fatal(err)
	}
	server, err := NewServerWithOptions(store, Options{CurrentSessionID: "current-session", Mode: "observe"})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var sessions []sqlite.SessionSummary
	if err := json.Unmarshal(response.Body.Bytes(), &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].SessionID != "current-session" || !sessions[0].Current || sessions[0].Actions != 0 || sessions[0].Mode != "observe" {
		t.Fatalf("sessions = %+v", sessions)
	}
}

func TestCurrentSessionDefaultsToObserveMode(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server, err := NewServerWithOptions(store, Options{CurrentSessionID: "current-session"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "current-session",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var sessions []sqlite.SessionSummary
	if err := json.Unmarshal(response.Body.Bytes(), &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Mode != "observe" {
		t.Fatalf("sessions = %+v, want current observe mode", sessions)
	}
}

func TestSessionsKeepPersistedModeAfterSessionChanges(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	enforceServer, err := NewServerWithOptions(store, Options{CurrentSessionID: "enforced-session", Mode: "enforce"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enforceServer.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "enforced-session",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	}); err != nil {
		t.Fatal(err)
	}
	observeServer, err := NewServerWithOptions(store, Options{CurrentSessionID: "observe-session", Mode: "observe"})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/sessions", nil)
	observeServer.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	var sessions []sqlite.SessionSummary
	if err := json.Unmarshal(response.Body.Bytes(), &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].SessionID != "enforced-session" || sessions[0].Current || sessions[0].Mode != "enforce" {
		t.Fatalf("sessions = %+v, want historical enforce mode", sessions)
	}
}
