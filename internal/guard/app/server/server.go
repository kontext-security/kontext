package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/policy"
	"github.com/kontext-security/kontext-cli/internal/guard/policyconfig"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	dashboardassets "github.com/kontext-security/kontext-cli/internal/guard/web/assets"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"
)

const (
	DefaultAddr            = "127.0.0.1:4765"
	devDashboardOrigin     = "http://127.0.0.1:5173"
	jsonContentType        = "application/json"
	unsupportedContentType = "policy profile requests require application/json"
	untrustedProfileOrigin = "untrusted policy profile origin"
)

type Server struct {
	store            *sqlite.Store
	policyStore      *policyconfig.Store
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
	Judge                judge.Judge
	PolicyConfig         policy.Config
	PolicyConfigProvider PolicyConfigProvider
	ProviderPolicies     []ProviderPolicyBinding
	EndpointID           string
	CurrentSessionID     string
	Mode                 string
	// RiskClassifier enables observe-mode risk-classifier logging for
	// intercepted bash commands. Nil disables it.
	RiskClassifier *RiskClassifierOptions
}

// RiskClassifierOptions configure the observe-mode risk classifier. The model
// is embedded, so enabling it needs no configuration today; the type exists so
// callers opt in explicitly and so the contract's deferred second-opinion LLM
// has somewhere to land.
type RiskClassifierOptions struct{}

type PolicyProfileResponse struct {
	Profile            policy.Profile `json:"profile"`
	RecommendedProfile policy.Profile `json:"recommended_profile"`
	Version            string         `json:"version"`
	RulePack           string         `json:"rule_pack"`
	RulePackVersion    string         `json:"rule_pack_version"`
	ConfigDigest       string         `json:"config_digest"`
	ActivationID       string         `json:"activation_id"`
	Source             string         `json:"source"`
	Status             string         `json:"status"`
	LoadedAt           time.Time      `json:"loaded_at"`
}

type ActivatePolicyProfileRequest struct {
	Profile policy.Profile `json:"profile"`
}

// ClassifierFeedbackRequest is the dashboard's ground-truth label for one
// observe-mode verdict: "should_allow" (false alarm) or "should_block" (miss).
type ClassifierFeedbackRequest struct {
	UserFeedback string `json:"user_feedback"`
}

func NewServer(store *sqlite.Store) (*Server, error) {
	return NewServerWithOptions(store, Options{})
}

// SetPayloadCaptureMode forwards the org's payload-capture directive to the
// store, which reads it per recorded action. Called by the managed daemon's
// policy refresh cycle whenever a snapshot is fetched or restored from disk.
func (s *Server) SetPayloadCaptureMode(mode payloadcapture.Mode) {
	s.store.SetPayloadCaptureMode(mode)
}

func NewServerWithOptions(store *sqlite.Store, opts Options) (*Server, error) {
	policyStore, err := openPolicyStoreForSQLite(store)
	if err != nil {
		return nil, err
	}
	configProvider := opts.PolicyConfigProvider
	if configProvider == nil {
		if explicitPolicyConfig(opts.PolicyConfig) {
			configProvider = staticPolicyConfigProvider{config: opts.PolicyConfig}
		} else {
			configProvider = policyStoreConfigProvider{store: policyStore}
		}
	}
	return NewServerWithPolicyConfigAndOptions(store, NewRiskPolicyProviderWithOptions(RiskPolicyProviderOptions{
		Judge:                opts.Judge,
		PolicyConfigProvider: configProvider,
		ProviderPolicies:     opts.ProviderPolicies,
		EndpointID:           opts.EndpointID,
	}), policyStore, opts)
}

// NewServerWithPolicy creates a Guard server with an injected policy provider.
// A nil interface uses the default local risk policy; callers must not pass a
// typed-nil provider because it still satisfies the PolicyProvider interface.
func NewServerWithPolicy(store *sqlite.Store, policy PolicyProvider) (*Server, error) {
	policyStore, err := openPolicyStoreForSQLite(store)
	if err != nil {
		return nil, err
	}
	return NewServerWithPolicyConfig(store, policy, policyStore)
}

func NewServerWithPolicyConfig(store *sqlite.Store, policy PolicyProvider, policyStore *policyconfig.Store) (*Server, error) {
	return NewServerWithPolicyConfigAndOptions(store, policy, policyStore, Options{})
}

func NewServerWithPolicyConfigAndOptions(store *sqlite.Store, policy PolicyProvider, policyStore *policyconfig.Store, opts Options) (*Server, error) {
	if policyStore == nil {
		var err error
		policyStore, err = openPolicyStoreForSQLite(store)
		if err != nil {
			return nil, err
		}
	}
	if _, err := policyStore.Load(context.Background()); err != nil {
		return nil, fmt.Errorf("load policy config: %w", err)
	}
	if policy == nil {
		policy = NewRiskPolicyProviderWithOptions(RiskPolicyProviderOptions{
			PolicyConfigProvider: policyStoreConfigProvider{store: policyStore},
		})
	}
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
		policyStore:      policyStore,
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
	return riskclassifier.NewObserver(riskclassifier.ObserverOptions{
		SVM:    svm,
		Redact: risk.RedactCredentials,
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
	return withCORS(s.mux)
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
	s.mux.HandleFunc("GET /api/policy/profile", s.handlePolicyProfile)
	s.mux.HandleFunc("POST /api/policy/profile", s.handleActivatePolicyProfile)
	s.mux.HandleFunc("POST /api/verdicts/{action_id}/feedback", s.handleClassifierFeedback)
	s.mux.HandleFunc("GET /", s.handleDashboard)
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

func (s *Server) handlePolicyProfile(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, policyProfileResponse(s.policyStore.Current()))
}

func (s *Server) handleActivatePolicyProfile(w http.ResponseWriter, r *http.Request) {
	if !trustedPolicyProfileRequest(r) {
		writeError(w, http.StatusForbidden, untrustedProfileOrigin)
		return
	}
	if !hasJSONContentType(r) {
		writeError(w, http.StatusUnsupportedMediaType, unsupportedContentType)
		return
	}
	var req ActivatePolicyProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid policy profile request")
		return
	}
	switch req.Profile {
	case policy.ProfileRelaxed, policy.ProfileBalanced, policy.ProfileStrict:
	default:
		writeError(w, http.StatusBadRequest, "unknown policy profile")
		return
	}
	snapshot, err := s.policyStore.ActivateProfile(r.Context(), req.Profile)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("activate policy profile: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, policyProfileResponse(snapshot))
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
		writeJSON(w, http.StatusOK, dashboardDecisionRecords(events))
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
// observe-mode verdict. Same trusted-origin gate as policy activation: the
// dashboard is the only writer.
func (s *Server) handleClassifierFeedback(w http.ResponseWriter, r *http.Request) {
	if !trustedPolicyProfileRequest(r) {
		writeError(w, http.StatusForbidden, untrustedProfileOrigin)
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

func dashboardDecisionRecords(records []sqlite.DecisionRecord) []sqlite.DecisionRecord {
	out := make([]sqlite.DecisionRecord, len(records))
	for i, record := range records {
		out[i] = record
		out[i].ModelVersion = ""
		out[i].RiskEvent.ModelVersion = ""
		out[i].RiskEvent.JudgeModel = ""
	}
	return out
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	dist, err := fs.Sub(dashboardassets.FS, "dist")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dashboard assets unavailable")
		return
	}
	http.FileServer(http.FS(dist)).ServeHTTP(w, r)
}

func policyProfileResponse(snapshot policyconfig.Snapshot) PolicyProfileResponse {
	return PolicyProfileResponse{
		Profile:            snapshot.Config.Profile,
		RecommendedProfile: policy.ProfileBalanced,
		Version:            snapshot.PolicyVersion,
		RulePack:           snapshot.RulePack,
		RulePackVersion:    snapshot.RulePackVersion,
		ConfigDigest:       snapshot.ConfigDigest,
		ActivationID:       snapshot.ActivationID,
		Source:             string(snapshot.Source),
		Status:             string(snapshot.Status),
		LoadedAt:           snapshot.LoadedAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func trustedPolicyProfileRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if origin == devDashboardOrigin {
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

type policyStoreConfigProvider struct {
	store *policyconfig.Store
}

func (p policyStoreConfigProvider) ActivePolicyConfig(context.Context) (policy.Config, error) {
	if p.store == nil {
		return policy.DefaultConfig(), nil
	}
	return p.store.Current().ToPolicyConfig(), nil
}

func explicitPolicyConfig(cfg policy.Config) bool {
	return cfg.Version != "" || cfg.Profile != "" || cfg.RulePack != "" || cfg.NonBypassableRules != nil
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:5173")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func openPolicyStoreForSQLite(store *sqlite.Store) (*policyconfig.Store, error) {
	if store == nil || store.Path() == "" {
		return nil, fmt.Errorf("policy config requires sqlite store path")
	}
	return policyconfig.Open(filepath.Dir(store.Path()))
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
