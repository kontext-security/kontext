package sessionpolicy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/cedarpolicy"
	"github.com/kontext-security/kontext-cli/internal/promptpolicy"
)

const defaultDerivationTimeout = 60 * time.Second

// SessionKey is the authority-bearing identity of one agent session. The
// installation is configured on Manager; Provider prevents native session IDs
// from different adapters sharing an authorization boundary.
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

// Snapshot is the single effective PolicySet selected for a session. Required
// with Ready=false is an explicit fail-closed barrier, not a fallback request.
type Snapshot struct {
	Required       bool
	Ready          bool
	PromptSequence uint64
	Deployment     *cedarpolicy.Deployment
	Failure        error
}

type Manager struct {
	deriver        Deriver
	validator      *promptpolicy.ActivationValidator
	parents        ParentSource
	tokenSource    TokenSource
	installationID string
	timeout        time.Duration

	mu       sync.Mutex
	sessions map[SessionKey]*session
}

type session struct {
	mu       sync.Mutex
	sequence uint64
	snapshot Snapshot
}

func NewManager(deriver Deriver, validator *promptpolicy.ActivationValidator, parents ParentSource, tokenSource TokenSource, installationID string, timeout time.Duration) (*Manager, error) {
	if deriver == nil || validator == nil || parents == nil || tokenSource == nil || installationID == "" {
		return nil, errors.New("prompt policy manager dependencies are incomplete")
	}
	if timeout <= 0 {
		timeout = defaultDerivationTimeout
	}
	return &Manager{deriver: deriver, validator: validator, parents: parents, tokenSource: tokenSource, installationID: installationID, timeout: timeout, sessions: make(map[SessionKey]*session)}, nil
}

// BeginPrompt is the synchronous policy barrier. It returns only after a new
// complete PolicySet has been verified, parsed, and atomically selected.
func (m *Manager) BeginPrompt(ctx context.Context, key SessionKey, prompt string) (Snapshot, error) {
	authorizationSessionID, err := key.AuthorizationSessionID()
	if err != nil {
		return Snapshot{}, err
	}
	if prompt == "" {
		return Snapshot{}, errors.New("prompt policy requires a prompt")
	}
	state := m.sessionFor(key)
	state.mu.Lock()
	defer state.mu.Unlock()

	state.sequence++
	sequence := state.sequence
	state.snapshot = Snapshot{Required: true, PromptSequence: sequence}

	parent := m.parents.Current().Deployment
	if parent == nil {
		err := errors.New("prompt policy parent is not ready")
		state.snapshot.Failure = err
		return state.snapshot, err
	}
	token, err := m.tokenSource(ctx)
	if err != nil {
		state.snapshot.Failure = fmt.Errorf("resolve prompt-policy token: %w", err)
		return state.snapshot, state.snapshot.Failure
	}
	requestCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()
	bundle, err := m.deriver.Put(requestCtx, promptpolicy.Request{
		Token: token, InstallationID: m.installationID,
		AuthorizationSessionID: authorizationSessionID, PromptSequence: sequence,
		Prompt: prompt, ParentDeploymentIdentity: parent.DeploymentIdentity,
	})
	if err != nil {
		state.snapshot.Failure = err
		return state.snapshot, err
	}
	if err := m.validator.Validate(bundle, promptpolicy.ExpectedAudience{
		InstallationID: m.installationID, AuthorizationSessionID: authorizationSessionID,
		PromptSequence: sequence, ParentDeploymentIdentity: parent.DeploymentIdentity,
	}); err != nil {
		state.snapshot.Failure = err
		return state.snapshot, err
	}
	if _, err := cedareval.New(bundle.PolicySet.Source); err != nil {
		state.snapshot.Failure = fmt.Errorf("parse effective prompt policy set: %w", err)
		return state.snapshot, state.snapshot.Failure
	}
	deployment := deploymentFromBundle(bundle)
	state.snapshot = Snapshot{Required: true, Ready: true, PromptSequence: sequence, Deployment: &deployment}
	return cloneSnapshot(state.snapshot), nil
}

func (m *Manager) SnapshotFor(key SessionKey) Snapshot {
	m.mu.Lock()
	state := m.sessions[key]
	m.mu.Unlock()
	if state == nil {
		return Snapshot{}
	}
	state.mu.Lock()
	defer state.mu.Unlock()
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

func deploymentFromBundle(bundle promptpolicy.Bundle) cedarpolicy.Deployment {
	return cedarpolicy.Deployment{
		ResponseVersion: bundle.ResponseVersion, RequestContractVersion: bundle.RequestContractVersion,
		PolicyHash: bundle.PolicySet.SourceHash, RolloutMode: cedareval.RolloutMode(bundle.RolloutMode),
		EvaluationPrincipal: cedareval.EvaluationPrincipal{EntityType: bundle.EvaluationPrincipal.EntityType, EntityID: bundle.EvaluationPrincipal.EntityID},
		PolicyText:          bundle.PolicySet.Source, DeploymentIdentity: bundle.DeploymentIdentity,
	}
}

func cloneSnapshot(snapshot Snapshot) Snapshot {
	if snapshot.Deployment != nil {
		deployment := *snapshot.Deployment
		snapshot.Deployment = &deployment
	}
	return snapshot
}
