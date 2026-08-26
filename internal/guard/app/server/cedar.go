package server

import (
	"context"
	"errors"
	"sync"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/hook"
)

const cedarEvaluatorVersion = "cedar-go/v1.8.0"

// CedarEnforcementSource selects who decides whether Cedar decisions are
// authoritative (real denies) or evidence-only (dry run).
type CedarEnforcementSource string

const (
	// CedarEnforcementOff keeps Cedar evidence-only regardless of the
	// deployment's rollout mode. This is the static observe posture.
	CedarEnforcementOff CedarEnforcementSource = ""
	// CedarEnforcementStatic makes Cedar authoritative whenever a policy is
	// distributed, with fail-closed unknown-state semantics (the local
	// cutover gate). This is the static enforce posture.
	CedarEnforcementStatic CedarEnforcementSource = "static"
	// CedarEnforcementRemote follows the fetched deployment's rollout mode:
	// Cedar is authoritative exactly when the deployment says enforce, and
	// evidence-only otherwise or while no deployment is cached.
	CedarEnforcementRemote CedarEnforcementSource = "remote"
)

type cedarPolicyProvider struct {
	current     PolicyProvider
	snapshots   cedarpolicy.SnapshotProvider
	enforcement CedarEnforcementSource

	mu             sync.Mutex
	evaluators     map[string]cachedEvaluator
	evaluatorOrder []string
}

type cachedEvaluator struct {
	evaluator *cedareval.Evaluator
	err       error
}

const maxCachedEvaluators = 32

func newCedarPolicyProvider(current PolicyProvider, snapshots cedarpolicy.SnapshotProvider, enforcement CedarEnforcementSource) PolicyProvider {
	if snapshots == nil {
		return current
	}
	return &cedarPolicyProvider{current: current, snapshots: snapshots, enforcement: enforcement, evaluators: make(map[string]cachedEvaluator)}
}

func (p *cedarPolicyProvider) DecideHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	if event.HookEventName != hook.HookPreToolUse.String() {
		return p.current.DecideHook(ctx, event)
	}

	snapshot := p.snapshots.Current()
	if sessions, ok := p.snapshots.(cedarpolicy.SessionSnapshotProvider); ok {
		snapshot = sessions.CurrentFor(event.SessionID, event.Agent)
	}
	claimsAuthority := p.claimsAuthority(snapshot)
	decision := risk.RiskDecision{}
	currentAction := cedareval.EffectiveExecutionActionAllow
	if claimsAuthority {
		riskEvent := risk.NormalizeHookEvent(event)
		riskEvent.Decision = risk.DecisionDeny
		decision = risk.RiskDecision{Decision: risk.DecisionDeny, Reason: "Cedar enforcement is not ready", ReasonCode: string(cedareval.ReasonEnforcementNotReady), RiskEvent: riskEvent}
	} else {
		var err error
		decision, err = p.current.DecideHook(ctx, event)
		if err != nil {
			return risk.RiskDecision{}, err
		}
		currentAction = executionAction(decision.Decision)
	}
	evidence := p.evaluate(snapshot, event, currentAction, claimsAuthority)
	decision.Cedar = &evidence
	if claimsAuthority {
		applyCedarDecision(&decision, evidence.Mapping)
	}
	return decision, nil
}

func (p *cedarPolicyProvider) claimsAuthority(snapshot cedarpolicy.Snapshot) bool {
	switch p.enforcement {
	case CedarEnforcementStatic:
		if snapshot.State == cedarpolicy.StateDisabled || snapshot.State == cedarpolicy.StateNoActivePolicy {
			return false
		}
		if snapshot.Status.Invalid {
			return true
		}
		policySet := snapshot.BestKnownPolicySet()
		if policySet == nil {
			// Once the local cutover gate is enabled, absence and untrusted
			// response states cannot silently restore the previous evaluator.
			// Only explicit disabled/no-active-policy states relinquish Cedar
			// authority.
			return true
		}
		return policySet.RolloutMode == string(cedareval.RolloutModeEnforce)
	case CedarEnforcementRemote:
		return cedarpolicy.DeploymentClaimsEnforce(snapshot)
	default:
		return false
	}
}

func (p *cedarPolicyProvider) evaluate(snapshot cedarpolicy.Snapshot, event risk.HookEvent, current cedareval.EffectiveExecutionAction, claimsAuthority bool) risk.CedarEvidence {
	evidence := risk.CedarEvidence{
		AppliedRolloutMode: cedareval.RolloutModeObserve,
		CacheFetchedAt:     snapshot.Status.FetchedAt,
		DistributionState:  string(snapshot.State),
		CacheStale:         snapshot.Status.Stale,
		CacheExpired:       snapshot.Status.Expired,
		CacheInvalid:       snapshot.Status.Invalid,
		EvaluatorVersion:   cedarEvaluatorVersion,
		ContextDiagnostics: []cedareval.ContextDiagnostic{},
	}
	outcome := cedareval.EvaluationOutcome{State: cedareval.EvaluationStateFailed, Reason: cedareval.ReasonPolicyMissing}
	var principal *cedareval.EvaluationPrincipal

	metadata := snapshot.BestKnownPolicySet()
	if metadata != nil {
		policySet := metadata
		evidence.ResponseVersion = policySet.ResponseVersion
		evidence.RequestContractVersion = policySet.RequestContractVersion
		evidence.PolicyHash = policySet.SourceHash
		evidence.DeploymentIdentity = policySet.DeploymentIdentity
		evidence.ConfiguredRolloutMode = cedareval.RolloutMode(policySet.RolloutMode)
		principalValue := policySet.EvaluationPrincipal
		principal = &principalValue

		if snapshot.ActivePolicySet() == nil {
			outcome.Reason = cedareval.ReasonStaleCachedPolicy
		} else if evaluator, parseErr := p.evaluatorFor(policySet); parseErr != nil {
			outcome.Reason = cedareval.ReasonInvalidCachedPolicy
			evidence.EngineErrorCount = 1
		} else {
			input, inputErr := cedareval.InputFromEvent(principalValue, hookEvent(event))
			if inputErr != nil {
				outcome.Reason = cedareval.ReasonRequestConversionFailed
			} else if result, evaluateErr := evaluator.Evaluate(input); evaluateErr != nil {
				var conversionErr *cedareval.ConversionError
				if errors.As(evaluateErr, &conversionErr) {
					outcome.Reason = cedareval.ReasonRequestConversionFailed
				} else {
					outcome.Reason = cedareval.ReasonEngineError
				}
				evidence.EngineErrorCount = 1
			} else {
				evidence.ContextDiagnostics = result.ContextDiagnostics
				evidence.EngineErrorCount = len(result.EngineDiagnostics.Errors)
				if evidence.EngineErrorCount > 0 {
					outcome = cedareval.EvaluationOutcome{
						State:  cedareval.EvaluationStateFailed,
						Reason: cedareval.ReasonEngineError,
					}
				} else {
					outcome = cedareval.EvaluationOutcome{
						State:                cedareval.EvaluationStateEvaluated,
						Decision:             result.Decision,
						Ask:                  result.Ask,
						DeterminingPolicyIDs: result.DeterminingPolicyIDs,
					}
				}
			}
		}
	} else if snapshot.Status.Invalid {
		outcome.Reason = cedareval.ReasonInvalidCachedPolicy
	} else if snapshot.Status.Stale {
		outcome.Reason = cedareval.ReasonStaleCachedPolicy
	}
	if isPrincipalState(snapshot.State) {
		principal = nil
		outcome = cedareval.EvaluationOutcome{State: cedareval.EvaluationStatePrincipalUnresolved, Reason: cedareval.ReasonPrincipalUnresolved}
	}

	appliedMode := cedareval.RolloutModeObserve
	enforcementReady := false
	currentAuthority := current
	if claimsAuthority {
		appliedMode = cedareval.RolloutModeEnforce
		enforcementReady = snapshot.ActivePolicySet() != nil && !snapshot.Status.Expired && !snapshot.Status.Invalid
		currentAuthority = ""
		if !enforcementReady {
			outcome = cedareval.EvaluationOutcome{State: cedareval.EvaluationStateNotEvaluated, Reason: cedareval.ReasonEnforcementNotReady}
		}
	}
	evidence.AppliedRolloutMode = appliedMode
	mapping, err := cedareval.MapDecision(cedareval.DecisionMappingInput{
		RolloutMode:            appliedMode,
		CurrentAuthorityAction: currentAuthority,
		EnforcementReady:       enforcementReady,
		EvaluationPrincipal:    principal,
		Evaluation:             outcome,
	})
	if err != nil {
		if claimsAuthority {
			// Fail closed: a ready-but-failed evaluation is the valid enforce
			// input and maps to a deny with the engine-error reason. Passing
			// EnforcementReady:false alongside a failed evaluation is the
			// contradictory input the mapper rejects, which would leave a
			// zero-value mapping that applyCedarDecision reads as allow. Never
			// discard the mapping error; if it somehow does not map, deny
			// explicitly.
			fallback, ferr := cedareval.MapDecision(cedareval.DecisionMappingInput{
				RolloutMode:      cedareval.RolloutModeEnforce,
				EnforcementReady: true,
				Evaluation:       cedareval.EvaluationOutcome{State: cedareval.EvaluationStateFailed, Reason: cedareval.ReasonEngineError},
			})
			if ferr != nil {
				fallback = cedareval.DecisionMapping{
					EvaluationState:          cedareval.EvaluationStateFailed,
					EffectiveExecutionAction: cedareval.EffectiveExecutionActionDeny,
					EvaluationReasonCode:     cedareval.ReasonEngineError,
					EffectiveReasonCode:      cedareval.ReasonEngineError,
					DeterminingPolicyIDs:     []string{},
				}
			}
			evidence.Mapping = fallback
			evidence.AppliedRolloutMode = cedareval.RolloutModeEnforce
			evidence.EngineErrorCount++
			return evidence
		}
		fallback, _ := cedareval.MapDecision(cedareval.DecisionMappingInput{
			RolloutMode:            cedareval.RolloutModeObserve,
			CurrentAuthorityAction: current,
			Evaluation:             cedareval.EvaluationOutcome{State: cedareval.EvaluationStateFailed, Reason: cedareval.ReasonEngineError},
		})
		evidence.Mapping = fallback
		evidence.AppliedRolloutMode = cedareval.RolloutModeObserve
		evidence.EngineErrorCount++
		return evidence
	}
	evidence.Mapping = mapping
	return evidence
}

func (p *cedarPolicyProvider) evaluatorFor(policySet *cedarpolicy.PolicySetSnapshot) (*cedareval.Evaluator, error) {
	if policySet.Evaluator != nil {
		return policySet.Evaluator, nil
	}
	p.mu.Lock()
	if cached, ok := p.evaluators[policySet.DeploymentIdentity]; ok {
		p.mu.Unlock()
		return cached.evaluator, cached.err
	}
	p.mu.Unlock()

	evaluator, err := cedareval.New(policySet.Source)

	p.mu.Lock()
	defer p.mu.Unlock()
	if cached, ok := p.evaluators[policySet.DeploymentIdentity]; ok {
		return cached.evaluator, cached.err
	}
	p.evaluators[policySet.DeploymentIdentity] = cachedEvaluator{evaluator: evaluator, err: err}
	p.evaluatorOrder = append(p.evaluatorOrder, policySet.DeploymentIdentity)
	if len(p.evaluatorOrder) > maxCachedEvaluators {
		oldest := p.evaluatorOrder[0]
		p.evaluatorOrder = p.evaluatorOrder[1:]
		delete(p.evaluators, oldest)
	}
	return evaluator, err
}

func executionAction(decision risk.Decision) cedareval.EffectiveExecutionAction {
	if decision == risk.DecisionDeny {
		return cedareval.EffectiveExecutionActionDeny
	}
	return cedareval.EffectiveExecutionActionAllow
}

func hookEvent(event risk.HookEvent) hook.Event {
	return hook.Event{SessionID: event.SessionID, Agent: event.Agent, HookName: hook.HookName(event.HookEventName), ToolName: event.ToolName, ToolInput: event.ToolInput, ToolResponse: event.ToolResponse, ToolUseID: event.ToolUseID, CWD: event.CWD}
}

func isPrincipalState(state cedarpolicy.State) bool {
	switch state {
	case cedarpolicy.StatePrincipalUnavailable:
		return true
	default:
		return false
	}
}

func applyCedarDecision(decision *risk.RiskDecision, mapping cedareval.DecisionMapping) {
	decision.ReasonCode = string(mapping.EffectiveReasonCode)
	decision.Reason = "local Cedar policy decision"
	decision.RiskEvent.ReasonCode = decision.ReasonCode
	decision.RiskEvent.DecisionStage = "cedar_policy"
	if mapping.EffectiveExecutionAction == cedareval.EffectiveExecutionActionDeny {
		decision.Decision = risk.DecisionDeny
		decision.RiskEvent.Decision = risk.DecisionDeny
		return
	}
	decision.Decision = risk.DecisionAllow
	decision.RiskEvent.Decision = risk.DecisionAllow
}
