package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/policy"
	"github.com/kontext-security/kontext-cli/internal/guard/policyconfig"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
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

func newTestServerWithPolicyConfig(t *testing.T, store *sqlite.Store, policyStore *policyconfig.Store) *Server {
	t.Helper()
	server, err := NewServerWithPolicyConfig(store, NewRiskPolicyProvider(), policyStore)
	if err != nil {
		t.Fatalf("NewServerWithPolicyConfig() error = %v", err)
	}
	return server
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
	if summary.Actions != 3 || summary.Warnings != 0 || summary.Critical != 2 || summary.Sessions != 1 {
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

func TestPolicyProfileGetReturnsLoadedDefault(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policyStore, err := policyconfig.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyConfig(t, store, policyStore)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/policy/profile", nil)
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response PolicyProfileResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Profile != policy.ProfileBalanced || response.RecommendedProfile != policy.ProfileBalanced {
		t.Fatalf("response = %+v, want default balanced profile", response)
	}
	if response.Version != policy.DefaultPolicyVersion || response.RulePack != policy.DefaultRulePackID || response.ActivationID == "" {
		t.Fatalf("response metadata = %+v", response)
	}
}

func TestPolicyProfilePostActivatesProfile(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policyStore, err := policyconfig.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyConfig(t, store, policyStore)

	body := bytes.NewBufferString(`{"profile":"strict"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/policy/profile", body)
	request.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	var response PolicyProfileResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Profile != policy.ProfileStrict {
		t.Fatalf("profile = %q, want strict", response.Profile)
	}
	if policyStore.Current().Config.Profile != policy.ProfileStrict {
		t.Fatalf("current profile = %q, want strict", policyStore.Current().Config.Profile)
	}
}

func TestPolicyProfilePostRejectsInvalidProfile(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policyStore, err := policyconfig.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyConfig(t, store, policyStore)
	initial := policyStore.Current()

	body := bytes.NewBufferString(`{"profile":"paranoid"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/policy/profile", body)
	request.Header.Set("Content-Type", "application/json")
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	current := policyStore.Current()
	if current.Config.Profile != initial.Config.Profile || current.ConfigDigest != initial.ConfigDigest {
		t.Fatalf("current = %+v, want unchanged %+v", current, initial)
	}
}

func TestPolicyProfilePostRejectsCrossOriginRequest(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policyStore, err := policyconfig.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyConfig(t, store, policyStore)
	initial := policyStore.Current()

	body := bytes.NewBufferString(`{"profile":"relaxed"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/policy/profile", body)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://example.test")
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusForbidden, recorder.Body.String())
	}
	current := policyStore.Current()
	if current.Config.Profile != initial.Config.Profile || current.ConfigDigest != initial.ConfigDigest {
		t.Fatalf("current = %+v, want unchanged %+v", current, initial)
	}
}

func TestPolicyProfilePostAllowsTrustedDashboardOrigins(t *testing.T) {
	tests := []struct {
		name   string
		target string
		origin string
	}{
		{name: "same origin", target: "http://127.0.0.1:4765/api/policy/profile", origin: "http://127.0.0.1:4765"},
		{name: "vite dev", target: "http://127.0.0.1:4765/api/policy/profile", origin: devDashboardOrigin},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			policyStore, err := policyconfig.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			server := newTestServerWithPolicyConfig(t, store, policyStore)

			body := bytes.NewBufferString(`{"profile":"strict"}`)
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, tt.target, body)
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", tt.origin)
			server.Handler().ServeHTTP(recorder, request)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
			}
			if policyStore.Current().Config.Profile != policy.ProfileStrict {
				t.Fatalf("current profile = %q, want strict", policyStore.Current().Config.Profile)
			}
		})
	}
}

func TestPolicyProfilePostRejectsSimpleContentType(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policyStore, err := policyconfig.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := newTestServerWithPolicyConfig(t, store, policyStore)
	initial := policyStore.Current()

	body := bytes.NewBufferString(`{"profile":"relaxed"}`)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/policy/profile", body)
	request.Header.Set("Content-Type", "text/plain")
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusUnsupportedMediaType, recorder.Body.String())
	}
	current := policyStore.Current()
	if current.Config.Profile != initial.Config.Profile || current.ConfigDigest != initial.ConfigDigest {
		t.Fatalf("current = %+v, want unchanged %+v", current, initial)
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

func TestDashboardEventsHideModelMetadata(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := recordingPolicy{
		decision: risk.RiskDecision{
			Decision:     risk.DecisionDeny,
			Reason:       "local judge denied",
			ReasonCode:   risk.DecisionStageJudgeDeny,
			ModelVersion: "qwen3-0.6b-q4",
			RiskEvent: risk.RiskEvent{
				Type:           risk.EventNormalToolCall,
				DecisionStage:  risk.DecisionStageJudgeDeny,
				ModelVersion:   "qwen3-0.6b-q4",
				JudgeModel:     "qwen3-0.6b-q4",
				JudgeRiskLevel: "high",
			},
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
		stored[0].ModelVersion != "qwen3-0.6b-q4" ||
		stored[0].RiskEvent.ModelVersion != "qwen3-0.6b-q4" ||
		stored[0].RiskEvent.JudgeModel != "qwen3-0.6b-q4" {
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
		response[0].RiskEvent.ModelVersion != "" ||
		response[0].RiskEvent.JudgeModel != "" {
		t.Fatalf("response = %+v, want model metadata hidden", response)
	}
}

func TestJudgePolicyDeniesFromLocalJudge(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionDeny,
				RiskLevel:  judge.RiskLevelHigh,
				Categories: []string{"destructive_operation"},
				Reason:     "Risky operation.",
			},
			Metadata: judge.Metadata{
				Runtime:    "openai-compatible",
				Model:      "qwen3-0.6b-q4",
				DurationMs: 12,
			},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "python scripts/deploy.py --dry-run"},
		CWD:           "/tmp/project",
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	if localJudge.input.ToolName != "Bash" || localJudge.input.ToolInput.Command != "python scripts/deploy.py --dry-run" {
		t.Fatalf("judge input = %+v", localJudge.input)
	}
	if decision.Decision != risk.DecisionDeny || decision.ReasonCode != "judge_deny" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.RiskEvent.DecisionStage != risk.DecisionStageJudgeDeny || decision.RiskEvent.JudgeModel != "qwen3-0.6b-q4" || decision.RiskEvent.JudgeRiskLevel != "high" {
		t.Fatalf("risk event = %+v", decision.RiskEvent)
	}
}

func TestJudgePolicyAllowsFromLocalJudge(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionAllow,
				RiskLevel:  judge.RiskLevelLow,
				Categories: []string{"normal_coding"},
				Reason:     "Safe local read.",
			},
			Metadata: judge.Metadata{
				Runtime:    "openai-compatible",
				Model:      "qwen3-0.6b-q4",
				DurationMs: 8,
			},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	if localJudge.input.ToolName != "Read" || localJudge.input.ToolInput.Path != "project_file" || localJudge.input.ToolInput.Request != "Read project_file" {
		t.Fatalf("judge input = %+v", localJudge.input)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != risk.DecisionStageJudgeAllow {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.RiskEvent.DecisionStage != risk.DecisionStageJudgeAllow || decision.RiskEvent.PolicyVersion != policy.DefaultPolicyVersion {
		t.Fatalf("risk event = %+v", decision.RiskEvent)
	}
}

func TestJudgePolicyRedactsCredentialValuesFromJudgeInput(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionAllow,
				RiskLevel:  judge.RiskLevelLow,
				Categories: []string{"normal_coding"},
				Reason:     "Safe.",
			},
			Metadata: judge.Metadata{Runtime: "openai-compatible", Model: "qwen3-0.6b-q4"},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": `echo API_TOKEN=real-secret-123`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	got := localJudge.input.ToolInput.Command
	if strings.Contains(got, "real-secret-123") {
		t.Fatalf("judge input leaked credential value: %+v", localJudge.input)
	}
	if !strings.Contains(got, payloadcapture.RedactedPlaceholder) {
		t.Fatalf("judge input missing redaction marker: %+v", localJudge.input)
	}
}

func TestJudgePolicyPreservesExplicitIntentForJudgeInput(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionAllow,
				RiskLevel:  judge.RiskLevelMedium,
				Categories: []string{"explicit_user_intent"},
				Reason:     "Approved preview action.",
			},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		Agent:         "claude",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "npm run deploy:preview approved_by_user"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	if !localJudge.input.ExplicitUserIntent {
		t.Fatalf("judge input missing explicit intent: %+v", localJudge.input)
	}
}

func TestJudgeInputClassifiesCredentialPathForNonReadTools(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantClass string
	}{
		{name: "env file", path: ".env", wantClass: "env_file"},
		{name: "relative aws credentials", path: ".aws/credentials", wantClass: "cloud_credentials"},
		{name: "dot relative gcloud credentials", path: "./.gcloud/application_default_credentials.json", wantClass: "cloud_credentials"},
		{name: "relative railway config", path: ".config/railway/config.json", wantClass: "cloud_credentials"},
		{name: "nested aws credentials", path: "nested/.aws/config", wantClass: "cloud_credentials"},
		{name: "normal project file", path: "README.md", wantClass: "project_file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := judgeInputFromRiskEvent(
				risk.HookEvent{
					ToolName:  "Write",
					ToolInput: map[string]any{"file_path": tt.path},
				},
				risk.RiskEvent{RequestSummary: "Write " + tt.path},
			)
			if input.ToolInput.Path != tt.wantClass {
				t.Fatalf("judge input path = %q, want %q: %+v", input.ToolInput.Path, tt.wantClass, input)
			}
			wantRequest := "Write " + tt.wantClass
			if tt.wantClass == "env_file" || tt.wantClass == "cloud_credentials" {
				wantRequest = "Write credential_path " + tt.wantClass
			}
			if input.ToolInput.Request != wantRequest {
				t.Fatalf("judge input request = %q, want %q: %+v", input.ToolInput.Request, wantRequest, input)
			}
			if strings.Contains(input.ToolInput.Request, tt.path) {
				t.Fatalf("judge input leaked raw path in request: %+v", input)
			}
		})
	}
}

func TestJudgeInputPreservesRedactedCommandSeparators(t *testing.T) {
	event := risk.HookEvent{
		ToolName:  "Bash",
		ToolInput: map[string]any{"command": "printf ok;TOKEN=secret echo next"},
	}
	riskEvent := risk.NormalizeHookEvent(event)
	input := judgeInputFromRiskEvent(event, riskEvent)

	if input.ToolInput.Command != "printf ok;TOKEN=[REDACTED_SECRET] echo next" {
		t.Fatalf("judge command = %q", input.ToolInput.Command)
	}
	if strings.Contains(input.ToolInput.Command, "secret") {
		t.Fatalf("judge command leaked credential: %q", input.ToolInput.Command)
	}
}

func TestJudgeInputDescribesPathOnlyLocalReads(t *testing.T) {
	rawPath := "/Users/michelosswald/.codex/worktrees/a693/kontext-cli/internal/guard/policy/types.go"
	input := judgeInputFromRiskEvent(
		risk.HookEvent{
			ToolName:  "Read",
			ToolInput: map[string]any{"file_path": rawPath},
		},
		risk.RiskEvent{RequestSummary: "Read " + rawPath},
	)
	if input.ToolInput.Path != "project_file" || input.ToolInput.Request != "Read project_file" {
		t.Fatalf("judge input = %+v, want sanitized local project read", input)
	}
	if strings.Contains(input.ToolInput.Request, rawPath) || strings.Contains(input.ToolInput.Request, "/Users/") {
		t.Fatalf("judge input leaked raw path in request: %+v", input)
	}
}

func TestJudgeInputIncludesSkillName(t *testing.T) {
	input := judgeInputFromRiskEvent(
		risk.HookEvent{
			ToolName:  "Skill",
			ToolInput: map[string]any{"skill": "review", "args": "ignored"},
		},
		risk.RiskEvent{RequestSummary: "Skill"},
	)
	if input.ToolInput.Request != "Skill review" {
		t.Fatalf("judge input request = %q, want %q", input.ToolInput.Request, "Skill review")
	}
}

func TestJudgeInputSkillWithoutNameFallsBack(t *testing.T) {
	input := judgeInputFromRiskEvent(
		risk.HookEvent{
			ToolName:  "Skill",
			ToolInput: map[string]any{},
		},
		risk.RiskEvent{RequestSummary: "Skill"},
	)
	if input.ToolInput.Request != "Skill" {
		t.Fatalf("judge input request = %q, want %q", input.ToolInput.Request, "Skill")
	}
}

func TestJudgePolicyFailsOpenWhenJudgeUnavailable(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server, err := NewServerWithOptions(store, Options{
		Judge: &recordingJudge{err: judge.Error{Kind: judge.FailureTimeout, Err: context.DeadlineExceeded}},
	})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "python scripts/deploy.py --dry-run"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != "judge_unavailable_allow" {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.RiskEvent.JudgeFailureKind != judge.FailureTimeout || decision.RiskEvent.DecisionStage != risk.DecisionStageJudgeFailOpen {
		t.Fatalf("risk event = %+v", decision.RiskEvent)
	}
}

func TestJudgePolicyDeterministicDecisionSkipsJudge(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "drop database"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 0 {
		t.Fatalf("judge calls = %d, want 0", localJudge.calls)
	}
	if decision.Decision != risk.DecisionDeny || decision.RiskEvent.DecisionStage != risk.DecisionStageDeterministicDeny {
		t.Fatalf("decision = %+v", decision)
	}
	if decision.RiskEvent.PolicyRuleID != "guard.destructive_persistent_resource.v1" ||
		decision.RiskEvent.PolicyRuleCategory != string(policy.CategoryDestructivePersistentResource) ||
		decision.RiskEvent.PolicyVersion != policy.DefaultPolicyVersion {
		t.Fatalf("policy metadata = %+v", decision.RiskEvent)
	}
}

func TestJudgePolicyUsesActiveProfileForDeterministicRules(t *testing.T) {
	dir := t.TempDir()
	policyStore, err := policyconfig.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policyStore.ActivateProfile(context.Background(), policy.ProfileRelaxed); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionAllow,
				RiskLevel:  judge.RiskLevelLow,
				Categories: []string{"explicit_profile"},
				Reason:     "Relaxed profile allows this to reach the judge.",
			},
			Metadata: judge.Metadata{Runtime: "openai-compatible", Model: "qwen3-0.6b-q4"},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": ".env"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	if localJudge.input.ToolName != "Read" || localJudge.input.ToolInput.Path != "env_file" {
		t.Fatalf("judge input = %+v", localJudge.input)
	}
	if decision.Decision != risk.DecisionAllow || decision.RiskEvent.PolicyProfile != string(policy.ProfileRelaxed) {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestJudgePolicyFallsBackWhenActivePolicyConfigInvalid(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "guard", "policy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "guard", "policy", "active.json"), []byte(`{"version":"invalid-active-policy","profile":"custom","rulePack":"guard-default","nonBypassableRules":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := sqlite.OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	localJudge := &recordingJudge{
		result: judge.Result{
			Output: judge.Output{
				Decision:   judge.DecisionAllow,
				RiskLevel:  judge.RiskLevelLow,
				Categories: []string{"fallback"},
				Reason:     "Fallback policy allowed this to reach the judge.",
			},
			Metadata: judge.Metadata{Runtime: "openai-compatible", Model: "qwen3-0.6b-q4"},
		},
	}
	server, err := NewServerWithOptions(store, Options{Judge: localJudge})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     map[string]any{"file_path": "README.md"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if localJudge.calls != 1 {
		t.Fatalf("judge calls = %d, want 1", localJudge.calls)
	}
	if localJudge.input.ToolName != "Read" || localJudge.input.ToolInput.Path != "project_file" {
		t.Fatalf("judge input = %+v", localJudge.input)
	}
	if decision.RiskEvent.PolicyVersion != policy.DefaultPolicyVersion || decision.RiskEvent.PolicyProfile != string(policy.ProfileBalanced) {
		t.Fatalf("risk event = %+v", decision.RiskEvent)
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

type recordingJudge struct {
	calls  int
	input  judge.Input
	result judge.Result
	err    error
}

func (j *recordingJudge) Decide(_ context.Context, input judge.Input) (judge.Result, error) {
	j.calls++
	j.input = input
	if j.err != nil {
		return judge.Result{}, j.err
	}
	return j.result, nil
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
	if len(sessions) != 1 || sessions[0].SessionID != "s1" || sessions[0].Critical != 1 {
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
