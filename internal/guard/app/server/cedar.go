package server

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/shellprojection"
	"github.com/kontext-security/kontext/internal/toolcatalog"
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
		if deployment != nil {
			return deployment.RolloutMode == cedareval.RolloutModeEnforce
		}
		legacy := snapshot.LegacyDeployment
		if legacy == nil {
			legacy = snapshot.LegacyLastKnownGood
		}
		if legacy == nil {
			// Once the local cutover gate is enabled, absence and untrusted
			// response states cannot silently restore the previous evaluator.
			// Only explicit disabled/no-active-policy states relinquish Cedar
			// authority.
			return true
		}
		return legacy.RolloutMode == cedareval.RolloutModeEnforce
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
	// Resolve the tool before any branch so the evidence always says what
	// policy saw (or would have seen), including in observe mode.
	toolID, projections := resolveTool(event)
	evidence.ToolID = toolID
	evidence.Shell = projections

	metadata := snapshot.Deployment
	if metadata == nil {
		metadata = snapshot.LastKnownGood
	}
	if metadata != nil {
		deployment := metadata
		evidence.ResponseVersion = deployment.ResponseVersion
		evidence.RequestContractVersion = deployment.RequestContractVersion
		evidence.PolicyHash = deployment.PolicySet.SourceHash
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
			inputs := cedarInputsV2(principalValue, event, toolID, projections)
			if result, evaluateErr := evaluateAll(evaluator, inputs); evaluateErr != nil {
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
	} else if legacy := legacyDeployment(snapshot); legacy != nil {
		evidence.ResponseVersion = legacy.ResponseVersion
		evidence.RequestContractVersion = legacy.RequestContractVersion
		evidence.PolicyHash = legacy.PolicyHash
		evidence.DeploymentIdentity = legacy.DeploymentIdentity
		evidence.ConfiguredRolloutMode = legacy.RolloutMode
		principalValue := legacy.EvaluationPrincipal
		principal = &principalValue

		if snapshot.LegacyDeployment == nil {
			outcome.Reason = cedareval.ReasonStaleCachedPolicy
		} else if evaluator, parseErr := p.legacyEvaluatorFor(legacy); parseErr != nil {
			outcome.Reason = cedareval.ReasonInvalidCachedPolicy
			evidence.EngineErrorCount = 1
		} else if input, inputErr := cedareval.InputFromEvent(principalValue, hookEvent(event)); inputErr != nil {
			outcome.Reason = cedareval.ReasonRequestConversionFailed
			evidence.EngineErrorCount = 1
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
				outcome = cedareval.EvaluationOutcome{State: cedareval.EvaluationStateFailed, Reason: cedareval.ReasonEngineError}
			} else {
				outcome = cedareval.EvaluationOutcome{State: cedareval.EvaluationStateEvaluated, Decision: result.Decision, Ask: result.Ask, DeterminingPolicyIDs: result.DeterminingPolicyIDs}
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
		enforcementReady = (snapshot.Deployment != nil || snapshot.LegacyDeployment != nil) && !snapshot.Status.Expired && !snapshot.Status.Invalid
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
		p.evaluator, p.parseErr = cedareval.New(deployment.PolicySet.Source)
	}
	return p.evaluator, p.parseErr
}

func (p *cedarPolicyProvider) legacyEvaluatorFor(deployment *cedarpolicy.LegacyDeployment) (*cedareval.Evaluator, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.identity != deployment.DeploymentIdentity {
		p.identity = deployment.DeploymentIdentity
		p.evaluator, p.parseErr = cedareval.New(deployment.PolicyText)
	}
	return p.evaluator, p.parseErr
}

func legacyDeployment(snapshot cedarpolicy.Snapshot) *cedarpolicy.LegacyDeployment {
	if snapshot.LegacyDeployment != nil {
		return snapshot.LegacyDeployment
	}
	return snapshot.LegacyLastKnownGood
}

// resolveTool maps a hook event to its catalog tool id. Shell commands are
// projected into one entry per call; every other tool is either a pinned
// GitHub MCP tool or unknown.
func resolveTool(event risk.HookEvent) (string, []cedareval.ShellProjectionV2) {
	if risk.IsShellTool(event.ToolName) {
		return cedareval.ToolShellV2, shellprojection.Project(risk.CommandFromInput(event.ToolInput))
	}
	if toolID, github := toolcatalog.Resolve(event.ToolName, event.ToolInput); github {
		return toolID, nil
	}
	return cedareval.ToolUnknownV2, nil
}

func cedarInputsV2(principal cedareval.EvaluationPrincipal, event risk.HookEvent, toolID string, projections []cedareval.ShellProjectionV2) []cedareval.ToolUseInputV2 {
	agentID := ""
	switch event.Agent {
	case "claude", "claude-code", cedareval.AgentClaudeCodeV2:
		agentID = cedareval.AgentClaudeCodeV2
	case "codex", cedareval.AgentCodexV2:
		agentID = cedareval.AgentCodexV2
	}
	base := cedareval.ToolUseInputV2{
		Version:    cedareval.RequestContractVersionV2,
		EndpointID: principal.EntityID,
		AgentID:    agentID,
		SessionID:  event.SessionID,
		ToolID:     toolID,
		ToolInput:  event.ToolInput,
	}
	if toolID != cedareval.ToolShellV2 {
		return []cedareval.ToolUseInputV2{base}
	}
	inputs := make([]cedareval.ToolUseInputV2, len(projections))
	for i := range projections {
		inputs[i] = base
		inputs[i].Shell = &projections[i]
	}
	return inputs
}

// evaluateAll evaluates one input per shell call and combines them: a single
// deny denies the command. The determining policies of a combined deny are
// only the forbids that fired, so the deny reason can name the rule instead
// of the permits that covered the harmless calls.
func evaluateAll(evaluator *cedareval.Evaluator, inputs []cedareval.ToolUseInputV2) (cedareval.Result, error) {
	combined := cedareval.Result{Decision: cedareval.DecisionAllow}
	permitIDs := map[string]struct{}{}
	forbidIDs := map[string]struct{}{}
	for _, input := range inputs {
		result, err := evaluator.EvaluateV2(input)
		if err != nil {
			return cedareval.Result{}, err
		}
		policyIDs := permitIDs
		if result.Decision == cedareval.DecisionDeny {
			combined.Decision = cedareval.DecisionDeny
			policyIDs = forbidIDs
		}
		combined.Ask = combined.Ask || result.Ask
		combined.ContextDiagnostics = append(combined.ContextDiagnostics, result.ContextDiagnostics...)
		combined.EngineDiagnostics.Errors = append(combined.EngineDiagnostics.Errors, result.EngineDiagnostics.Errors...)
		combined.EngineDiagnostics.Reasons = append(combined.EngineDiagnostics.Reasons, result.EngineDiagnostics.Reasons...)
		for _, policyID := range result.DeterminingPolicyIDs {
			policyIDs[policyID] = struct{}{}
		}
	}
	determining := permitIDs
	if combined.Decision == cedareval.DecisionDeny {
		determining = forbidIDs
	}
	for policyID := range determining {
		combined.DeterminingPolicyIDs = append(combined.DeterminingPolicyIDs, policyID)
	}
	sort.Strings(combined.DeterminingPolicyIDs)
	return combined, nil
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
	decision.Reason = cedarDecisionReason(mapping)
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

// cedarDecisionReason names the forbid rule (its @id) behind an enforced
// deny, which is what the agent and the operator see in the hook message.
// Denies without a rule (enforcement not ready, engine errors, unavailable
// ask) keep the generic wording.
func cedarDecisionReason(mapping cedareval.DecisionMapping) string {
	if mapping.EffectiveExecutionAction == cedareval.EffectiveExecutionActionDeny &&
		mapping.DerivedCedarAction == cedareval.DerivedCedarActionDeny &&
		len(mapping.DeterminingPolicyIDs) > 0 {
		return "Blocked by rule " + strings.Join(mapping.DeterminingPolicyIDs, ", ")
	}
	return "local Cedar policy decision"
}
