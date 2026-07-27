package server

import (
	"context"
	"errors"
	"sync"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	"github.com/kontext-security/kontext-cli/internal/cedarpolicy"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/hook"
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

	mu        sync.Mutex
	identity  string
	evaluator *cedareval.Evaluator
	parseErr  error
}

func newCedarPolicyProvider(current PolicyProvider, snapshots cedarpolicy.SnapshotProvider, enforcement CedarEnforcementSource) PolicyProvider {
	if snapshots == nil {
		return current
	}
	return &cedarPolicyProvider{current: current, snapshots: snapshots, enforcement: enforcement}
}

func (p *cedarPolicyProvider) DecideHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	if event.HookEventName != hook.HookPreToolUse.String() {
		return p.current.DecideHook(ctx, event)
	}

	snapshot := p.snapshots.Current()
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
		deployment := snapshot.Deployment
		if deployment == nil {
			deployment = snapshot.LastKnownGood
		}
		if deployment == nil {
			// Once the local cutover gate is enabled, absence and untrusted
			// response states cannot silently restore the previous evaluator.
			// Only explicit disabled/no-active-policy states relinquish Cedar
			// authority.
			return true
		}
		return deployment.RolloutMode == cedareval.RolloutModeEnforce
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

	metadata := snapshot.Deployment
	if metadata == nil {
		metadata = snapshot.LastKnownGood
	}
	if metadata != nil {
		deployment := metadata
		evidence.ResponseVersion = deployment.ResponseVersion
		evidence.RequestContractVersion = deployment.RequestContractVersion
		evidence.PolicyHash = deployment.PolicyHash
		evidence.DeploymentIdentity = deployment.DeploymentIdentity
		evidence.ConfiguredRolloutMode = deployment.RolloutMode
		principalValue := deployment.EvaluationPrincipal
		principal = &principalValue

		if snapshot.Deployment == nil {
			outcome.Reason = cedareval.ReasonStaleCachedPolicy
		} else if evaluator, parseErr := p.evaluatorFor(deployment); parseErr != nil {
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
		enforcementReady = snapshot.Deployment != nil && !snapshot.Status.Expired && !snapshot.Status.Invalid
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

func (p *cedarPolicyProvider) evaluatorFor(deployment *cedarpolicy.Deployment) (*cedareval.Evaluator, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.identity != deployment.DeploymentIdentity {
		p.identity = deployment.DeploymentIdentity
		p.evaluator, p.parseErr = cedareval.New(deployment.PolicyText)
	}
	return p.evaluator, p.parseErr
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
