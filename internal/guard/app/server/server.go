package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/cedarpolicy"
	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"
)

const (
	DefaultAddr             = "127.0.0.1:4765"
	untrustedFeedbackOrigin = "untrusted classifier feedback origin"
	jsonContentType         = "application/json"
	unsupportedContentType  = "policy profile requests require application/json"
)

type Server struct {
	store            *sqlite.Store
	core             *runtimecore.Core
	mux              *http.ServeMux
	currentSessionID string
	mode             string
	classifier       *riskclassifier.Observer
}

type ProcessResponse struct {
	Decision   risk.Decision `json:"decision"`
	Reason     string        `json:"reason"`
	ReasonCode string        `json:"reason_code"`
	EventID    string        `json:"event_id"`
}

type Options struct {
	Judge            judge.Judge
	CedarPolicies    cedarpolicy.SnapshotProvider
	CedarEnforcement CedarEnforcementSource
	CurrentSessionID string
	Mode             string
	// RiskClassifier enables observe-mode risk-classifier logging for
	// intercepted bash commands. Nil disables it; the guardrail LLM inside is
	// optional independently.
	RiskClassifier *RiskClassifierOptions
}

// RiskClassifierOptions configure the observe-mode risk classifier. The SVM is
// embedded and always available; the guardrail LLM reuses the local judge's
// llama-server endpoint when one is running.
type RiskClassifierOptions struct {
	GuardrailBaseURL string
	GuardrailModel   string
	GuardrailTimeout time.Duration
}

// ClassifierFeedbackRequest is the dashboard's ground-truth label for one
// observe-mode verdict: "should_allow" (false alarm) or "should_block" (miss).
type ClassifierFeedbackRequest struct {
	UserFeedback string `json:"user_feedback"`
}

func NewServer(store *sqlite.Store) (*Server, error) {
	return NewServerWithOptions(store, Options{})
}

func (s *Server) SetPayloadCaptureConfiguration(config payloadcapture.RuntimeConfiguration) {
	s.store.SetPayloadCaptureConfiguration(config)
}

func NewServerWithOptions(store *sqlite.Store, opts Options) (*Server, error) {
	return NewServerWithPolicyAndOptions(store, NewRiskPolicyProviderWithJudge(opts.Judge), opts)
}

// NewServerWithPolicy creates a Guard server with an injected policy provider.
// A nil interface uses the default local risk policy; callers must not pass a
// typed-nil provider because it still satisfies the PolicyProvider interface.
func NewServerWithPolicy(store *sqlite.Store, policy PolicyProvider) (*Server, error) {
	return NewServerWithPolicyAndOptions(store, policy, Options{})
}

func NewServerWithPolicyAndOptions(store *sqlite.Store, policy PolicyProvider, opts Options) (*Server, error) {
	if policy == nil {
		policy = NewRiskPolicyProvider()
	}
	policy = newCedarPolicyProvider(policy, opts.CedarPolicies, opts.CedarEnforcement)
	currentSessionID := strings.TrimSpace(opts.CurrentSessionID)
	mode := strings.TrimSpace(opts.Mode)
	if currentSessionID != "" && mode == "" {
		mode = "observe"
	}
	classifier := newRiskClassifierObserver(store, opts.RiskClassifier)
	runtime := newGuardHookRuntime(store, policy, currentSessionID, mode, classifier)
	core, err := runtimecore.New(runtime)
	if err != nil {
		classifier.Close()
		return nil, fmt.Errorf("create runtime core: %w", err)
	}
	server := &Server{
		store:            store,
		core:             core,
		mux:              http.NewServeMux(),
		currentSessionID: currentSessionID,
		mode:             mode,
		classifier:       classifier,
	}
	server.routes()
	return server, nil
}

// newRiskClassifierObserver builds the observe-mode classifier pipeline. Every
// failure here degrades to nil (classifier off) rather than blocking startup:
// this path only collects feedback data and must never keep Guard from running.
func newRiskClassifierObserver(store *sqlite.Store, opts *RiskClassifierOptions) *riskclassifier.Observer {
	if opts == nil || store == nil {
		return nil
	}
	svm, err := riskclassifier.LoadSVM()
	if err != nil {
		return nil
	}
	var guardrail *riskclassifier.Guardrail
	if strings.TrimSpace(opts.GuardrailBaseURL) != "" && strings.TrimSpace(opts.GuardrailModel) != "" {
		guardrail, err = riskclassifier.NewGuardrail(riskclassifier.GuardrailOptions{
			BaseURL: opts.GuardrailBaseURL,
			Model:   opts.GuardrailModel,
			Timeout: opts.GuardrailTimeout,
		})
		if err != nil {
			guardrail = nil
		}
	}
	return riskclassifier.NewObserver(riskclassifier.ObserverOptions{
		SVM:       svm,
		Guardrail: guardrail,
		Redact:    risk.RedactCredentials,
		Sink: func(ctx context.Context, record riskclassifier.Record) error {
			_, err := store.SaveClassifierVerdict(ctx, record)
			return err
		},
	})
}

// CloseRiskClassifier stops the observe-mode classifier, draining queued
// records. Safe on a nil server or a disabled classifier.
func (s *Server) CloseRiskClassifier() {
	if s == nil {
		return
	}
	s.classifier.Close()
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) RuntimeCore() *runtimecore.Core {
	return s.core
}

func (s *Server) ListenAndServe(addr string) error {
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return httpServer.ListenAndServe()
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("POST /api/hooks/evaluate", s.handleEvaluate)
	s.mux.HandleFunc("POST /api/hooks/ingest", s.handleIngest)
	s.mux.HandleFunc("POST /api/hooks/process", s.handleProcess)
	s.mux.HandleFunc("GET /api/summary", s.handleSummary)
	s.mux.HandleFunc("GET /api/sessions", s.handleSessions)
	s.mux.HandleFunc("GET /api/sessions/", s.handleSession)
	s.mux.HandleFunc("POST /api/verdicts/{action_id}/feedback", s.handleClassifierFeedback)
}

func (s *Server) EvaluateHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	result, err := s.core.EvaluateHook(ctx, hookEventFromRiskEvent(event))
	if err != nil {
		return risk.RiskDecision{}, err
	}
	return riskDecisionFromHookResult(result), nil
}

func (s *Server) IngestEvent(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	result, err := s.core.IngestEvent(ctx, hookEventFromRiskEvent(event))
	if err != nil {
		return risk.RiskDecision{}, err
	}
	return riskDecisionFromHookResult(result), nil
}

func (s *Server) ProcessHookEvent(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	result, err := s.core.ProcessHook(ctx, hookEventFromRiskEvent(event))
	if err != nil {
		return risk.RiskDecision{}, err
	}
	return riskDecisionFromHookResult(result), nil
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	s.handleHook(w, r, s.EvaluateHook)
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	s.handleHook(w, r, s.IngestEvent)
}

func (s *Server) handleProcess(w http.ResponseWriter, r *http.Request) {
	s.handleHook(w, r, s.ProcessHookEvent)
}

func (s *Server) handleHook(w http.ResponseWriter, r *http.Request, process func(context.Context, risk.HookEvent) (risk.RiskDecision, error)) {
	var event risk.HookEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		writeError(w, http.StatusBadRequest, "invalid hook event")
		return
	}
	decision, err := process(r.Context(), event)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ProcessResponse{
		Decision:   decision.Decision,
		Reason:     decision.Reason,
		ReasonCode: decision.ReasonCode,
		EventID:    decision.EventID,
	})
}

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	summary, err := s.store.Summary(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.store.Sessions(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sessions = s.withCurrentSession(r.Context(), sessions)
	writeJSON(w, http.StatusOK, sessions)
}

func (s *Server) withCurrentSession(ctx context.Context, sessions []sqlite.SessionSummary) []sqlite.SessionSummary {
	if s.currentSessionID == "" {
		return sessions
	}
	for i := range sessions {
		if sessions[i].SessionID == s.currentSessionID {
			sessions[i].Current = true
			if mode := s.modeForSession(sessions[i].SessionID); mode != "" {
				sessions[i].Mode = mode
			}
			return sessions
		}
	}
	record, err := s.store.Session(ctx, s.currentSessionID)
	if err != nil {
		return sessions
	}
	return append([]sqlite.SessionSummary{{
		SessionID: record.ID,
		Actions:   0,
		LatestAt:  record.UpdatedAt,
		Status:    record.Status,
		CreatedAt: record.CreatedAt,
		UpdatedAt: record.UpdatedAt,
		ClosedAt:  record.ClosedAt,
		Current:   true,
		Mode:      s.modeForSession(record.ID),
	}}, sessions...)
}

func (s *Server) modeForSession(sessionID string) string {
	if sessionID == "" || sessionID != s.currentSessionID {
		return ""
	}
	return s.mode
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/api/sessions/")
	parts := strings.Split(strings.Trim(trimmed, "/"), "/")
	if len(parts) != 2 || parts[0] == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	sessionID := parts[0]
	switch parts[1] {
	case "summary":
		summary, err := s.store.SessionSummary(r.Context(), sessionID)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if mode := s.modeForSession(sessionID); mode != "" {
			summary.Mode = mode
		}
		writeJSON(w, http.StatusOK, summary)
	case "events":
		events, err := s.store.Events(r.Context(), sessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, redactedDecisionRecords(events))
	case "verdicts":
		verdicts, err := s.store.ClassifierVerdictsForSession(r.Context(), sessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, verdicts)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

// handleClassifierFeedback records the user's ground-truth label on an
// observe-mode verdict. Writes are same-origin only: this is a loopback API on a
// developer machine, and nothing reachable from a browsed page should be able to
// forge training labels.
func (s *Server) handleClassifierFeedback(w http.ResponseWriter, r *http.Request) {
	if !sameOriginRequest(r) {
		writeError(w, http.StatusForbidden, untrustedFeedbackOrigin)
		return
	}
	if !hasJSONContentType(r) {
		writeError(w, http.StatusUnsupportedMediaType, "classifier feedback requires application/json")
		return
	}
	actionID := r.PathValue("action_id")
	if strings.TrimSpace(actionID) == "" {
		writeError(w, http.StatusBadRequest, "action id is required")
		return
	}
	var req ClassifierFeedbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid classifier feedback request")
		return
	}
	switch req.UserFeedback {
	case riskclassifier.FeedbackShouldAllow, riskclassifier.FeedbackShouldBlock:
	default:
		writeError(w, http.StatusBadRequest, "unknown classifier feedback")
		return
	}
	record, err := s.store.SetClassifierFeedback(r.Context(), actionID, req.UserFeedback)
	if errors.Is(err, sqlite.ErrClassifierVerdictNotFound) {
		writeError(w, http.StatusNotFound, "classifier verdict not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func redactedDecisionRecords(records []sqlite.DecisionRecord) []sqlite.DecisionRecord {
	out := make([]sqlite.DecisionRecord, len(records))
	for i, record := range records {
		out[i] = record
		out[i].ModelVersion = ""
		out[i].RiskEvent.ModelVersion = ""
		out[i].RiskEvent.JudgeModel = ""
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// sameOriginRequest allows a request with no Origin (a direct client such as
// curl or the CLI) or one whose Origin matches this server, plus the Vite dev
// server used while working on the dashboard. Anything else is a cross-site
// caller and must not be able to write feedback labels.
func sameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Scheme == "http" && parsed.Host == r.Host
}

func hasJSONContentType(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, jsonContentType)
}

func OpenDefaultServer(dbPath string) (*Server, func() error, error) {
	return OpenDefaultServerWithOptions(dbPath, Options{})
}

func OpenDefaultServerWithOptions(dbPath string, opts Options) (*Server, func() error, error) {
	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open store: %w", err)
	}
	server, err := NewServerWithOptions(store, opts)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	return server, store.Close, nil
}
