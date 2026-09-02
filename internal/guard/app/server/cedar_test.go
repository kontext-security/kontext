package server

import (
	"context"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/cedareval"
	"github.com/kontext-security/kontext/internal/cedarpolicy"
	"github.com/kontext-security/kontext/internal/guard/risk"
)

type staticCedarSnapshots struct{ snapshot cedarpolicy.Snapshot }

func (s staticCedarSnapshots) Current() cedarpolicy.Snapshot { return s.snapshot }

type staticHookPolicy struct{ decision risk.RiskDecision }

func (p staticHookPolicy) DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error) {
	return p.decision, nil
}

type countingHookPolicy struct {
	decision risk.RiskDecision
	calls    int
}

const portableEngineErrorPolicy = `@id("allow")
permit(principal, action == Kontext::Action::"ToolUse", resource);

@id("erroring_forbid")
forbid(principal, action == Kontext::Action::"ToolUse", resource) when { context.shell.program == "git" };`

const cedarTestSchema = `namespace Kontext {
  entity Endpoint;
  entity Agent;
  entity Tool;
  action "ToolUse" appliesTo {
    principal: [Endpoint],
    resource: [Tool],
    context: {}
  };
}`

const cedarTestToolCatalogDigest = "f86247e4b2a3f0121a482c1ba9cc8f6913e4d22f73478b66237bbdbe5ff26b92"

func cedarHookEvent(tool string, input map[string]any) risk.HookEvent {
	return risk.HookEvent{SessionID: "session-1", Agent: "claude", HookEventName: "PreToolUse", ToolName: tool, ToolInput: input}
}

func (p *countingHookPolicy) DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error) {
	p.calls++
	return p.decision, nil
}

func TestCedarObservePreservesCurrentAuthorityAndRecordsDecision(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"unknown");`)
	current := staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionDeny, Reason: "current deny", ReasonCode: "current_deny", RiskEvent: risk.RiskEvent{Decision: risk.DecisionDeny}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{FetchedAt: time.Now()}}}, CedarEnforcementOff)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionDeny || decision.ReasonCode != "current_deny" {
		t.Fatalf("effective decision = %#v, want unchanged current authority", decision)
	}
	if decision.Cedar == nil || decision.Cedar.AppliedRolloutMode != cedareval.RolloutModeObserve {
		t.Fatalf("Cedar evidence = %#v, want observe", decision.Cedar)
	}
	if decision.Cedar.Mapping.DerivedCedarAction != cedareval.DerivedCedarActionAllow {
		t.Fatalf("derived action = %q, want allow", decision.Cedar.Mapping.DerivedCedarAction)
	}
	if decision.Cedar.Mapping.EffectiveExecutionAction != cedareval.EffectiveExecutionActionDeny {
		t.Fatalf("effective Cedar mapping = %q, want current deny", decision.Cedar.Mapping.EffectiveExecutionAction)
	}
}

func TestCedarObserveClassifiesContextConversionFailure(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeObserve, `@id("permit") permit(principal, action, resource);`)
	current := staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementOff)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{"bad": make(chan struct{})}))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Cedar.Mapping.EvaluationReasonCode != cedareval.ReasonRequestConversionFailed {
		t.Fatalf("evaluation reason = %q, want conversion failure", decision.Cedar.Mapping.EvaluationReasonCode)
	}
	if decision.Decision != risk.DecisionAllow {
		t.Fatal("observe failure changed current authority")
	}
}

func TestCedarObserveClassifiesEngineDiagnosticsAsFailure(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeObserve, portableEngineErrorPolicy)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, ReasonCode: "current_allow", RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementOff)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{"command": 1}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 1 || decision.Decision != risk.DecisionAllow {
		t.Fatalf("calls = %d decision = %#v, want preserved current authority", current.calls, decision)
	}
	if decision.Cedar == nil || decision.Cedar.EngineErrorCount != 1 {
		t.Fatalf("Cedar evidence = %#v, want one engine error", decision.Cedar)
	}
	if decision.Cedar.Mapping.EvaluationState != cedareval.EvaluationStateFailed || decision.Cedar.Mapping.EvaluationReasonCode != cedareval.ReasonEngineError {
		t.Fatalf("mapping = %#v, want failed/engine_error", decision.Cedar.Mapping)
	}
	if len(decision.Cedar.Mapping.DeterminingPolicyIDs) != 0 {
		t.Fatalf("determining policy ids = %v, want none for failed evaluation", decision.Cedar.Mapping.DeterminingPolicyIDs)
	}
}

func TestCedarObserveRecordsUnresolvedPrincipal(t *testing.T) {
	current := staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: cedarpolicy.StatePrincipalUnavailable}}, CedarEnforcementOff)
	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Cedar.Mapping.EvaluationState != cedareval.EvaluationStatePrincipalUnresolved || decision.Cedar.Mapping.EvaluationPrincipal != nil {
		t.Fatalf("mapping = %#v, want unresolved principal without identity", decision.Cedar.Mapping)
	}
}

func TestCedarEnforceIsSingularAuthority(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"unknown");`)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionDeny, ReasonCode: "legacy_deny"}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{FetchedAt: time.Now()}}}, CedarEnforcementStatic)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 0 {
		t.Fatalf("previous evaluator calls = %d, want zero after cutover", current.calls)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != string(cedareval.ReasonPermit) {
		t.Fatalf("decision = %#v, want Cedar allow", decision)
	}
}

func TestCedarEnforceDeniesAskWithoutApprovalChannel(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("ask-write") @ask("prompt") permit(principal, action, resource == Kontext::Tool::"unknown");`)
	current := &countingHookPolicy{}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementStatic)
	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Write", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionDeny || decision.ReasonCode != string(cedareval.ReasonAskUnavailable) {
		t.Fatalf("decision = %#v, want ask fail-closed", decision)
	}
}

func TestCedarEnforceFailsClosedOnEngineDiagnostics(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, portableEngineErrorPolicy)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementStatic)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{"command": 1}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 0 {
		t.Fatalf("previous evaluator calls = %d, want zero after cutover", current.calls)
	}
	if decision.Decision != risk.DecisionDeny || decision.ReasonCode != string(cedareval.ReasonEngineError) {
		t.Fatalf("decision = %#v, want fail-closed engine_error deny", decision)
	}
	if decision.Cedar == nil || decision.Cedar.EngineErrorCount != 1 || decision.Cedar.Mapping.EvaluationState != cedareval.EvaluationStateFailed {
		t.Fatalf("Cedar evidence = %#v, want failed evaluation with one engine error", decision.Cedar)
	}
	if len(decision.Cedar.Mapping.DeterminingPolicyIDs) != 0 {
		t.Fatalf("determining policy ids = %v, want none for failed evaluation", decision.Cedar.Mapping.DeterminingPolicyIDs)
	}
}

func TestCedarEnforceFailsClosedWithoutFallback(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit") permit(principal, action, resource);`)
	tests := []struct {
		name     string
		snapshot cedarpolicy.Snapshot
	}{
		{name: "expired cache", snapshot: cedarpolicy.Snapshot{LastKnownGood: &deployment, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{Stale: true, Expired: true}}},
		{name: "invalid cache", snapshot: cedarpolicy.Snapshot{Status: cedarpolicy.CacheStatus{Invalid: true, Stale: true, Expired: true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}
			provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: tt.snapshot}, CedarEnforcementStatic)
			decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
			if err != nil {
				t.Fatal(err)
			}
			if current.calls != 0 || decision.Decision != risk.DecisionDeny || decision.ReasonCode != string(cedareval.ReasonEnforcementNotReady) {
				t.Fatalf("calls = %d decision = %#v, want no fallback and deny", current.calls, decision)
			}
		})
	}
}

func TestCedarExplicitDisableReturnsAuthorityToCurrentEvaluator(t *testing.T) {
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, ReasonCode: "current_allow", RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: cedarpolicy.StateDisabled}}, CedarEnforcementStatic)
	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 1 || decision.Decision != risk.DecisionAllow || decision.Cedar.AppliedRolloutMode != cedareval.RolloutModeObserve {
		t.Fatalf("calls = %d decision = %#v, want explicit rollback", current.calls, decision)
	}
}

func TestCedarEnforceDoesNotFallbackOnNonRollbackResponseStates(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit") permit(principal, action, resource);`)
	states := []cedarpolicy.State{
		cedarpolicy.StatePrincipalUnavailable,
		cedarpolicy.StateUnsupportedVersion,
		cedarpolicy.StateUnauthorized,
	}
	for _, state := range states {
		t.Run(string(state), func(t *testing.T) {
			current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}
			provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{
				LastKnownGood: &deployment,
				State:         state,
			}}, CedarEnforcementStatic)
			decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
			if err != nil {
				t.Fatal(err)
			}
			if current.calls != 0 || decision.Decision != risk.DecisionDeny {
				t.Fatalf("calls = %d decision = %#v, want retained Cedar authority and deny", current.calls, decision)
			}
		})
	}
}

func TestCedarEnforceFailsClosedWithoutLastKnownGood(t *testing.T) {
	states := []cedarpolicy.State{
		"",
		cedarpolicy.StatePrincipalUnavailable,
		cedarpolicy.StateUnsupportedVersion,
		cedarpolicy.StateUnauthorized,
	}
	for _, state := range states {
		name := string(state)
		if name == "" {
			name = "missing"
		}
		t.Run(name, func(t *testing.T) {
			current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}
			provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: state}}, CedarEnforcementStatic)
			decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
			if err != nil {
				t.Fatal(err)
			}
			if current.calls != 0 || decision.Decision != risk.DecisionDeny || decision.ReasonCode != string(cedareval.ReasonEnforcementNotReady) {
				t.Fatalf("calls = %d decision = %#v, want fail-closed Cedar authority", current.calls, decision)
			}
		})
	}
}

func TestCedarConfiguredObserveKeepsCurrentAuthority(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeObserve, `@id("forbid-all") forbid(principal, action, resource);`)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, ReasonCode: "current_allow", RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementStatic)
	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 1 || decision.Decision != risk.DecisionAllow || decision.Cedar.AppliedRolloutMode != cedareval.RolloutModeObserve {
		t.Fatalf("calls = %d decision = %#v, want current observe authority", current.calls, decision)
	}
}

func TestCedarNoActivePolicyIsExplicitRollback(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit") permit(principal, action, resource);`)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{LastKnownGood: &deployment, State: cedarpolicy.StateNoActivePolicy}}, CedarEnforcementStatic)
	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 1 || decision.Decision != risk.DecisionAllow {
		t.Fatalf("calls = %d decision = %#v, want explicit no-policy rollback", current.calls, decision)
	}
}

func TestCedarEnforceUsesAgeValidLastKnownGoodAfterRefreshFailure(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit") permit(principal, action, resource);`)
	current := &countingHookPolicy{}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{
		Deployment:    &deployment,
		LastKnownGood: &deployment,
		State:         cedarpolicy.StateSuccess,
		Status:        cedarpolicy.CacheStatus{Stale: true},
	}}, CedarEnforcementStatic)
	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 0 || decision.Decision != risk.DecisionAllow {
		t.Fatalf("calls = %d decision = %#v, want age-valid LKG authority", current.calls, decision)
	}
}

func cedarTestDeployment(t *testing.T, mode cedareval.RolloutMode, policy string) cedarpolicy.Deployment {
	t.Helper()
	principal := cedareval.EvaluationPrincipal{EntityType: cedareval.EndpointEntityTypeV2, EntityID: "ins_12345678901234567890123456789012"}
	policyHash := cedareval.ComputePolicyHash(policy)
	schemaHash := cedareval.ComputeSchemaHash(cedarTestSchema)
	identity, err := cedareval.ComputeDeploymentIdentityV2(cedareval.DeploymentIdentityV2Input{
		ResponseVersion:        cedarpolicy.ResponseVersion,
		RequestContractVersion: cedarpolicy.RequestContractVersion,
		PolicySetSourceHash:    policyHash,
		SchemaHash:             schemaHash,
		ToolCatalogDigest:      cedarTestToolCatalogDigest,
		RolloutMode:            string(mode),
		EvaluationPrincipal:    principal,
	})
	if err != nil {
		t.Fatal(err)
	}
	return cedarpolicy.Deployment{
		ResponseVersion:        cedarpolicy.ResponseVersion,
		RequestContractVersion: cedarpolicy.RequestContractVersion,
		PolicySet:              cedarpolicy.PolicySet{Source: policy, SourceHash: policyHash},
		Schema:                 cedarpolicy.Schema{Source: cedarTestSchema, Hash: schemaHash},
		ToolCatalogDigest:      cedarTestToolCatalogDigest,
		RolloutMode:            mode,
		EvaluationPrincipal:    principal,
		DeploymentIdentity:     identity,
	}
}

func TestCedarRemoteFollowsEnforceRollout(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"unknown");`)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionDeny, ReasonCode: "legacy_deny"}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{FetchedAt: time.Now()}}}, CedarEnforcementRemote)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 0 {
		t.Fatalf("previous evaluator calls = %d, want zero under remote enforce rollout", current.calls)
	}
	if decision.Decision != risk.DecisionAllow || decision.ReasonCode != string(cedareval.ReasonPermit) {
		t.Fatalf("decision = %#v, want Cedar allow", decision)
	}
	if decision.Cedar == nil || decision.Cedar.AppliedRolloutMode != cedareval.RolloutModeEnforce {
		t.Fatalf("Cedar evidence = %#v, want applied enforce", decision.Cedar)
	}
}

func TestCedarStaticEvaluatesVersionOneCacheDuringUpgrade(t *testing.T) {
	policy := `@id("permit") permit(principal, action, resource);`
	principal := cedareval.EvaluationPrincipal{EntityType: cedareval.PrincipalEntityType, EntityID: "ins_12345678901234567890123456789012"}
	policyHash := cedareval.ComputePolicyHash(policy)
	identity, err := cedareval.ComputeDeploymentIdentity(cedareval.DeploymentIdentityInput{
		ResponseVersion: 1, RequestContractVersion: 1, PolicyHash: policyHash,
		RolloutMode: string(cedareval.RolloutModeEnforce), EvaluationPrincipal: principal,
	})
	if err != nil {
		t.Fatal(err)
	}
	legacy := cedarpolicy.LegacyDeployment{
		ResponseVersion: 1, RequestContractVersion: 1, PolicyHash: policyHash,
		RolloutMode: cedareval.RolloutModeEnforce, EvaluationPrincipal: principal,
		PolicyText: policy, DeploymentIdentity: identity,
	}
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionDeny}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{
		LegacyDeployment: &legacy, LegacyLastKnownGood: &legacy, State: cedarpolicy.StateSuccess,
	}}, CedarEnforcementStatic)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 0 || decision.Decision != risk.DecisionAllow {
		t.Fatalf("calls = %d decision = %#v, want cached v1 Cedar permit", current.calls, decision)
	}
}

func TestCedarRemoteStaysObserveUnderObserveRollout(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeObserve, `@id("forbid-read") forbid(principal, action, resource == Kontext::Tool::"unknown");`)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, ReasonCode: "current_allow", RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{FetchedAt: time.Now()}}}, CedarEnforcementRemote)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 1 || decision.Decision != risk.DecisionAllow || decision.ReasonCode != "current_allow" {
		t.Fatalf("calls = %d decision = %#v, want preserved current authority under observe rollout", current.calls, decision)
	}
	if decision.Cedar == nil || decision.Cedar.AppliedRolloutMode != cedareval.RolloutModeObserve {
		t.Fatalf("Cedar evidence = %#v, want dry-run observe", decision.Cedar)
	}
}

func TestCedarRemoteWithoutDeploymentStaysObserve(t *testing.T) {
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: cedarpolicy.StateUnavailable}}, CedarEnforcementRemote)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 1 || decision.Decision != risk.DecisionAllow {
		t.Fatalf("calls = %d decision = %#v, want fail-open observe before first deployment", current.calls, decision)
	}
}

func TestCedarRemoteHoldsLastKnownGoodEnforce(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"unknown");`)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{
		LastKnownGood: &deployment,
		State:         cedarpolicy.StateUnavailable,
	}}, CedarEnforcementRemote)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 0 || decision.Decision != risk.DecisionDeny || decision.ReasonCode != string(cedareval.ReasonEnforcementNotReady) {
		t.Fatalf("calls = %d decision = %#v, want fail-closed enforcement while only LKG enforce is cached", current.calls, decision)
	}
}

func TestCedarRemoteDisabledStateRelinquishesAuthority(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"unknown");`)
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{
		LastKnownGood: &deployment,
		State:         cedarpolicy.StateDisabled,
	}}, CedarEnforcementRemote)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 1 || decision.Decision != risk.DecisionAllow {
		t.Fatalf("calls = %d decision = %#v, want current authority after explicit disable", current.calls, decision)
	}
}
