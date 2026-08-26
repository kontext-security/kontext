package sessionpolicy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/promptpolicy"
)

const defaultDerivationTimeout = 58 * time.Second

type SessionKey struct {
	Provider        string
	NativeSessionID string
}

func (k SessionKey) AuthorizationSessionID() (string, error) {
	if k.Provider == "" || k.NativeSessionID == "" {
		return "", errors.New("prompt policy requires provider and native session id")
	}
	return k.Provider + ":" + k.NativeSessionID, nil
}

type Deriver interface {
	Put(context.Context, promptpolicy.Request) (promptpolicy.Bundle, error)
}

type TokenSource func(context.Context) (string, error)

type ParentSource interface {
	Current() cedarpolicy.Snapshot
}

type SessionState string

const (
	SessionStateIdle    SessionState = ""
	SessionStatePending SessionState = "pending"
	SessionStateActive  SessionState = "active"
	SessionStateFailed  SessionState = "failed"
)

type Snapshot struct {
	State                    SessionState
	PromptSequence           uint64
	PolicySet                *cedarpolicy.PolicySetSnapshot
	ParentDeploymentIdentity string
	Failure                  error
	ExpiresAt                time.Time
}

type Manager struct {
	deriver        Deriver
	validator      *promptpolicy.ActivationValidator
	parents        ParentSource
	tokenSource    TokenSource
	installationID string
	timeout        time.Duration
	daemonEpoch    string
	configMu       sync.RWMutex
	enabled        bool

	mu       sync.Mutex
	sessions map[SessionKey]*session
}

type session struct {
	operationMu sync.Mutex
	mu          sync.RWMutex
	sequence    uint64
	snapshot    Snapshot
}

func NewManager(deriver Deriver, validator *promptpolicy.ActivationValidator, parents ParentSource, tokenSource TokenSource, installationID string, timeout time.Duration) (*Manager, error) {
	if deriver == nil || validator == nil || parents == nil || tokenSource == nil || installationID == "" {
		return nil, errors.New("prompt policy manager dependencies are incomplete")
	}
	if timeout <= 0 {
		timeout = defaultDerivationTimeout
	}
	epoch, err := newDaemonEpoch()
	if err != nil {
		return nil, fmt.Errorf("create prompt-policy daemon epoch: %w", err)
	}
	return &Manager{deriver: deriver, validator: validator, parents: parents, tokenSource: tokenSource, installationID: installationID, timeout: timeout, daemonEpoch: epoch, sessions: make(map[SessionKey]*session)}, nil
}

// BeginPrompt synchronously establishes the policy barrier. Snapshot readers
// never wait on its network work: they immediately see required/not-ready.
func (m *Manager) BeginPrompt(ctx context.Context, key SessionKey, prompt string) (Snapshot, error) {
	baseSessionID, err := key.AuthorizationSessionID()
	if err != nil {
		return Snapshot{}, err
	}
	if prompt == "" {
		return Snapshot{}, errors.New("prompt policy requires a prompt")
	}
	m.configMu.RLock()
	if !m.enabled {
		m.configMu.RUnlock()
		return Snapshot{}, nil
	}
	state := m.sessionFor(key)
	state.mu.Lock()
	state.sequence++
	sequence := state.sequence
	state.snapshot = Snapshot{State: SessionStatePending, PromptSequence: sequence}
	state.mu.Unlock()
	m.configMu.RUnlock()

	state.operationMu.Lock()
	defer state.operationMu.Unlock()
	state.mu.RLock()
	if state.sequence != sequence {
		snapshot := cloneSnapshot(state.snapshot)
		state.mu.RUnlock()
		return snapshot, nil
	}
	state.mu.RUnlock()

	parentSnapshot := m.parents.Current()
	parent := parentSnapshot.ActivePolicySet()
	if parentSnapshot.State != cedarpolicy.StateSuccess || parent == nil {
		failure := errors.New("prompt policy parent is not ready")
		return m.failIfCurrent(state, sequence, failure), failure
	}
	token, err := m.tokenSource(ctx)
	if err != nil {
		failure := fmt.Errorf("resolve prompt-policy token: %w", err)
		return m.failIfCurrent(state, sequence, failure), failure
	}
	authorizationSessionID := baseSessionID + ":" + m.daemonEpoch
	requestCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	request := promptpolicy.Request{
		Token: token, InstallationID: m.installationID,
		AuthorizationSessionID: authorizationSessionID, PromptSequence: sequence,
		Prompt: prompt, ParentDeploymentIdentity: parent.DeploymentIdentity,
	}
	bundle, err := m.deriveWithRetry(requestCtx, request)
	if err != nil {
		return m.failIfCurrent(state, sequence, err), err
	}
	if err := m.validator.Validate(bundle, promptpolicy.ExpectedAudience{
		InstallationID: m.installationID, AuthorizationSessionID: authorizationSessionID,
		PromptSequence: sequence, ParentDeploymentIdentity: parent.DeploymentIdentity,
		RolloutMode: parent.RolloutMode,
	}); err != nil {
		return m.failIfCurrent(state, sequence, err), err
	}
	evaluator, err := cedareval.New(bundle.PolicySet.Source)
	if err != nil {
		failure := fmt.Errorf("parse effective prompt policy set: %w", err)
		return m.failIfCurrent(state, sequence, failure), failure
	}
	policySet := policySetFromBundle(bundle, evaluator)
	expiresAt, _ := time.Parse(time.RFC3339Nano, bundle.ExpiresAt)
	state.mu.Lock()
	if state.sequence == sequence {
		state.snapshot = Snapshot{State: SessionStateActive, PromptSequence: sequence, PolicySet: &policySet, ParentDeploymentIdentity: bundle.Parent.DeploymentIdentity, ExpiresAt: expiresAt}
	}
	snapshot := cloneSnapshot(state.snapshot)
	state.mu.Unlock()
	return snapshot, nil
}

func (m *Manager) deriveWithRetry(ctx context.Context, request promptpolicy.Request) (promptpolicy.Bundle, error) {
	for attempt := 0; ; attempt++ {
		bundle, err := m.deriver.Put(ctx, request)
		if err == nil || attempt >= 2 {
			return bundle, err
		}
		var httpError *promptpolicy.HTTPError
		var transportError *promptpolicy.TransportError
		retryDelay := 100 * time.Millisecond
		if errors.As(err, &httpError) {
			if !httpError.Response.Retryable {
				return promptpolicy.Bundle{}, err
			}
			retryDelay = httpError.RetryAfter
		} else if !errors.As(err, &transportError) {
			return promptpolicy.Bundle{}, err
		}
		timer := time.NewTimer(retryDelay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return promptpolicy.Bundle{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (m *Manager) Current() cedarpolicy.Snapshot { return m.parents.Current() }

func (m *Manager) CurrentFor(sessionID, agent string) cedarpolicy.Snapshot {
	base := m.parents.Current()
	m.configMu.RLock()
	defer m.configMu.RUnlock()
	if !m.enabled {
		return base
	}
	selected := m.SnapshotFor(SessionKey{Provider: agent, NativeSessionID: sessionID})
	if selected.State == SessionStateIdle {
		return unavailableSnapshot(base, "no prompt policy is active for this session")
	}
	parent := base.ActivePolicySet()
	parentMatches := parent != nil && parent.DeploymentIdentity == selected.ParentDeploymentIdentity
	parentEligible := base.State == cedarpolicy.StateSuccess && !base.Status.Invalid && !base.Status.Expired
	if selected.State == SessionStateActive && selected.PolicySet != nil && parentMatches && parentEligible && time.Now().Before(selected.ExpiresAt) {
		return cedarpolicy.Snapshot{PolicySet: selected.PolicySet, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{State: cedarpolicy.StateSuccess, FetchedAt: time.Now()}}
	}
	return unavailableSnapshot(base, "required prompt policy is not ready or its parent changed")
}

func (m *Manager) SetEnabled(enabled bool) {
	m.configMu.Lock()
	defer m.configMu.Unlock()
	m.enabled = enabled
	if !enabled {
		m.mu.Lock()
		m.sessions = make(map[SessionKey]*session)
		m.mu.Unlock()
	}
}

func (m *Manager) SnapshotFor(key SessionKey) Snapshot {
	m.mu.Lock()
	state := m.sessions[key]
	m.mu.Unlock()
	if state == nil {
		return Snapshot{}
	}
	state.mu.RLock()
	defer state.mu.RUnlock()
	return cloneSnapshot(state.snapshot)
}

func (m *Manager) EndSession(key SessionKey) {
	m.mu.Lock()
	delete(m.sessions, key)
	m.mu.Unlock()
}

func (m *Manager) sessionFor(key SessionKey) *session {
	m.mu.Lock()
	defer m.mu.Unlock()
	if current := m.sessions[key]; current != nil {
		return current
	}
	created := &session{}
	m.sessions[key] = created
	return created
}

func (m *Manager) failIfCurrent(state *session, sequence uint64, failure error) Snapshot {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.sequence == sequence {
		state.snapshot = Snapshot{State: SessionStateFailed, PromptSequence: sequence, Failure: failure}
	}
	return cloneSnapshot(state.snapshot)
}

func policySetFromBundle(bundle promptpolicy.Bundle, evaluator *cedareval.Evaluator) cedarpolicy.PolicySetSnapshot {
	return cedarpolicy.PolicySetSnapshot{ResponseVersion: bundle.ResponseVersion, RequestContractVersion: bundle.CedarRequestContractVersion, SourceHash: bundle.PolicySet.SourceHash, RolloutMode: bundle.RolloutMode, EvaluationPrincipal: cedareval.EvaluationPrincipal{EntityType: bundle.EvaluationPrincipal.EntityType, EntityID: bundle.EvaluationPrincipal.EntityID}, Source: bundle.PolicySet.Source, DeploymentIdentity: bundle.DeploymentIdentity, Evaluator: evaluator}
}

func unavailableSnapshot(base cedarpolicy.Snapshot, reason string) cedarpolicy.Snapshot {
	lastKnownParent := base.Deployment
	if lastKnownParent == nil {
		lastKnownParent = base.LastKnownGood
	}
	return cedarpolicy.Snapshot{LastKnownGood: lastKnownParent, State: cedarpolicy.StateUnavailable, Status: cedarpolicy.CacheStatus{State: cedarpolicy.StateUnavailable, Invalid: true, LastError: reason}}
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	if snapshot.PolicySet != nil {
		policySet := *snapshot.PolicySet
		snapshot.PolicySet = &policySet
	}
	return snapshot
}

func newDaemonEpoch() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
