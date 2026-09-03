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

const cedarTestToolCatalogDigest = "cf87ee7a167f1f07bdc41450467708f832c9d8c4aaf20651a5d0df070d3de436"

func cedarHookEvent(tool string, input map[string]any) risk.HookEvent {
	return risk.HookEvent{SessionID: "session-1", Agent: "claude", HookEventName: "PreToolUse", ToolName: tool, ToolInput: input}
}

func (p *countingHookPolicy) DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error) {
	p.calls++
	return p.decision, nil
}

func TestCedarObservePreservesCurrentAuthorityAndRecordsDecision(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"Read");`)
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
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"Read");`)
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
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("ask-write") @ask("prompt") permit(principal, action, resource == Kontext::Tool::"Write");`)
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
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"Read");`)
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

func TestCedarRemoteFailsClosedWhenPersistedEnforceCacheIsIncompatible(t *testing.T) {
	current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{
		PersistedEnforce: true,
		State:            cedarpolicy.StateSuccess,
		Status:           cedarpolicy.CacheStatus{Invalid: true, Stale: true},
	}}, CedarEnforcementRemote)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if current.calls != 0 || decision.Decision != risk.DecisionDeny || decision.ReasonCode != string(cedareval.ReasonEnforcementNotReady) {
		t.Fatalf("calls = %d decision = %#v, want persisted enforce claim to fail closed", current.calls, decision)
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
	deployment := cedarTestDeployment(t, cedareval.RolloutModeObserve, `@id("forbid-read") forbid(principal, action, resource == Kontext::Tool::"Read");`)
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

const githubForcePushPolicy = `@id("allow")
permit(principal, action == Kontext::Action::"ToolUse", resource);

@id("github-block-force-push")
forbid(principal, action == Kontext::Action::"ToolUse", resource == Kontext::Tool::"shell")
when { context.shell.facts.contains("github/force-push=true") };`

func TestCedarShellForcePushObserveAndEnforce(t *testing.T) {
	event := cedarHookEvent("Bash", map[string]any{"command": "git status; git push -f origin main"})
	for _, test := range []struct {
		name        string
		enforcement CedarEnforcementSource
		want        risk.Decision
	}{
		{"observe", CedarEnforcementOff, risk.DecisionAllow},
		{"enforce", CedarEnforcementRemote, risk.DecisionDeny},
	} {
		t.Run(test.name, func(t *testing.T) {
			deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, githubForcePushPolicy)
			current := &countingHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, ReasonCode: "current_allow", RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
			provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, test.enforcement)

			decision, err := provider.DecideHook(context.Background(), event)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Decision != test.want {
				t.Fatalf("decision = %q, want %q", decision.Decision, test.want)
			}
			if decision.Cedar == nil || decision.Cedar.Mapping.DerivedCedarAction != cedareval.DerivedCedarActionDeny {
				t.Fatalf("Cedar evidence = %#v, want force-push deny", decision.Cedar)
			}
		})
	}
}

func TestCedarEnforceDenyReasonNamesRule(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, githubForcePushPolicy)
	provider := newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": "git status; git push -f origin main"}))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionDeny || decision.Reason != "Blocked by rule github-block-force-push" {
		t.Fatalf("decision = %#v, want deny naming the forbid rule", decision)
	}
	if ids := decision.Cedar.Mapping.DeterminingPolicyIDs; len(ids) != 1 || ids[0] != "github-block-force-push" {
		t.Fatalf("determining policy ids = %v, want only the forbid that fired", ids)
	}

	allowed, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": "git status"}))
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Decision != risk.DecisionAllow || allowed.Reason != "local Cedar policy decision" {
		t.Fatalf("decision = %#v, want generic wording on allow", allowed)
	}
}

func TestCedarEnforceKeepsGenericReasonWithoutRule(t *testing.T) {
	provider := newCedarPolicyProvider(&countingHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: cedarpolicy.StateUnauthorized}}, CedarEnforcementStatic)
	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionDeny || decision.Reason != "local Cedar policy decision" {
		t.Fatalf("decision = %#v, want generic fail-closed wording", decision)
	}
}

func TestCedarEvidenceCarriesToolIDAndShellFacts(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeObserve, githubForcePushPolicy)
	current := staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementOff)

	shell, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": "git push -fu origin main"}))
	if err != nil {
		t.Fatal(err)
	}
	if shell.Decision != risk.DecisionAllow || shell.Cedar.AppliedRolloutMode != cedareval.RolloutModeObserve {
		t.Fatalf("decision = %#v, want observe to keep current authority", shell)
	}
	if shell.Cedar.ToolID != cedareval.ToolShellV2 || len(shell.Cedar.Shell) != 1 || shell.Cedar.Shell[0].Program != "git" {
		t.Fatalf("Cedar evidence = %#v, want shell tool id and one git projection", shell.Cedar)
	}
	if facts := shell.Cedar.Shell[0].Facts; !containsString(facts, "github/force-push=true") {
		t.Fatalf("shell facts = %v, want force-push fact in observe evidence", facts)
	}
	if shell.Cedar.Mapping.DerivedCedarAction != cedareval.DerivedCedarActionDeny {
		t.Fatalf("mapping = %#v, want observed deny", shell.Cedar.Mapping)
	}

	mcp, err := provider.DecideHook(context.Background(), cedarHookEvent("mcp__gh__get_me", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if mcp.Cedar.ToolID != "github-mcp/get_me" || mcp.Cedar.Shell != nil {
		t.Fatalf("Cedar evidence = %#v, want resolved GitHub tool id without shell", mcp.Cedar)
	}

	other, err := provider.DecideHook(context.Background(), cedarHookEvent("Read", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if other.Cedar.ToolID != "Read" {
		t.Fatalf("Cedar evidence = %#v, want the reported tool name as id", other.Cedar)
	}
}

func TestCedarEvidenceResolvesToolWithoutDeployment(t *testing.T) {
	current := staticHookPolicy{decision: risk.RiskDecision{Decision: risk.DecisionAllow, RiskEvent: risk.RiskEvent{Decision: risk.DecisionAllow}}}
	provider := newCedarPolicyProvider(current, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{State: cedarpolicy.StateUnavailable}}, CedarEnforcementRemote)
	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": "git push -f origin main"}))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Cedar.ToolID != cedareval.ToolShellV2 || len(decision.Cedar.Shell) != 1 {
		t.Fatalf("Cedar evidence = %#v, want tool id and projections even before the first deployment", decision.Cedar)
	}
}

// TestCedarEnforceKeepsRunningOnCatalogSkew is the daemon-restart-after-
// upgrade case: the cached deployment carries another catalog digest, and the
// preset must still deny what it was written to deny.
func TestCedarEnforceKeepsRunningOnCatalogSkew(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, githubForcePushPolicy)
	deployment.ToolCatalogDigest = "0000000000000000000000000000000000000000000000000000000000000000"
	if deployment.MatchesToolCatalog() {
		t.Fatal("test deployment must carry a skewed catalog digest")
	}
	snapshot := cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess, Status: cedarpolicy.CacheStatus{Stale: true, CatalogMismatch: true}}
	provider := newCedarPolicyProvider(&countingHookPolicy{}, staticCedarSnapshots{snapshot: snapshot}, CedarEnforcementRemote)

	denied, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": "git push -f origin main"}))
	if err != nil {
		t.Fatal(err)
	}
	if denied.Decision != risk.DecisionDeny || denied.Reason != "Blocked by rule github-block-force-push" {
		t.Fatalf("decision = %#v, want enforced deny on skewed catalog", denied)
	}
	allowed, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": "git status"}))
	if err != nil {
		t.Fatal(err)
	}
	if allowed.Decision != risk.DecisionAllow {
		t.Fatalf("decision = %#v, want enforced allow on skewed catalog", allowed)
	}
}

// TestCedarForcePushProbeCorpus runs the probe commands from the live hook
// session through the force-push preset shape. Every bypass must now deny.
func TestCedarForcePushProbeCorpus(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, githubForcePushPolicy)
	provider := newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)

	denied := []string{
		"git push -f origin main",
		"git push -fu origin main",
		"git push -uf origin main",
		"git push origin +main",
		"git push origin +HEAD:main",
		`\git push -f origin main`,
		"exec git push -f origin main",
		"timeout 30 git push -f origin main",
		"bash -c 'git push -f origin main'",
		`sh -c "git push --force origin main"`,
		`eval "git push -f origin main"`,
		"nohup git push -f origin main",
		"nice -n 5 git push -f origin main",
		"time git push -f origin main",
		"echo main | xargs git push -f origin",
		"git -c alias.x=y push -f origin main",
		"git --no-optional-locks push -f origin main",
		"git -p push -f origin main",
		"git push -f $REMOTE main",
		"git status; git push -f origin main",
	}
	for _, command := range denied {
		decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": command}))
		if err != nil {
			t.Fatal(err)
		}
		if decision.Decision != risk.DecisionDeny {
			t.Errorf("%q: decision = %#v, want deny", command, decision)
		}
	}

	allowed := []string{
		"git status",
		"git push origin main",
		"git push --force-with-lease origin main",
		"git push --dry-run -f origin main",
		"git push -fn origin main",
		"bash -c 'git status'",
		"command -v git",
		"gh pr view 42",
	}
	for _, command := range allowed {
		decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": command}))
		if err != nil {
			t.Fatal(err)
		}
		if decision.Decision != risk.DecisionAllow {
			t.Errorf("%q: decision = %#v, want allow", command, decision)
		}
	}
}

// TestCedarParseFailureIsPolicyDecided keeps unparseable commands out of the
// engine-error path: the projection reports the failure as a fact and the
// force-push preset alone does not deny them.
func TestCedarParseFailureIsPolicyDecided(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, githubForcePushPolicy)
	provider := newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": "git push -f origin main; ("}))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionAllow || decision.Cedar.EngineErrorCount != 0 {
		t.Fatalf("decision = %#v, want policy-decided allow without engine error", decision)
	}
	if len(decision.Cedar.Shell) != 1 || !containsString(decision.Cedar.Shell[0].Features, "shell/parse-error") {
		t.Fatalf("shell evidence = %#v, want parse-error feature", decision.Cedar.Shell)
	}

	strict := cedarTestDeployment(t, cedareval.RolloutModeEnforce, githubForcePushPolicy+`
@id("github-block-unparseable")
forbid(principal, action == Kontext::Action::"ToolUse", resource == Kontext::Tool::"shell")
when { context.shell.features.contains("shell/parse-error") };`)
	strictProvider := newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &strict, LastKnownGood: &strict, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
	decision, err = strictProvider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": "git push -f origin main; ("}))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionDeny || decision.Reason != "Blocked by rule github-block-unparseable" {
		t.Fatalf("decision = %#v, want strict policy to deny unparseable commands", decision)
	}
}

// githubPresetsPolicy mirrors the three cloud GitHub presets: force pushes,
// writes, and unrecognized GitHub operations. A typo in an unrelated command
// or a dynamic program must not trip any of them.
const githubPresetsPolicy = `@id("allow")
permit(principal, action == Kontext::Action::"ToolUse", resource);

@id("block-github-force-push")
forbid(principal, action == Kontext::Action::"ToolUse", resource == Kontext::Tool::"shell")
when { context.shell.facts.contains("github/force-push=true") };

@id("block-github-writes")
forbid(principal, action == Kontext::Action::"ToolUse", resource == Kontext::Tool::"shell")
when { context.shell.facts.contains("github/write=true") };

@id("block-unrecognized-github-operations")
forbid(principal, action == Kontext::Action::"ToolUse", resource == Kontext::Tool::"shell")
when { context.shell.facts.contains("github/route=unrecognized") };`

func TestCedarGitHubPresetsIgnoreUnrelatedFailures(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, githubPresetsPolicy)
	provider := newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)

	allowed := []string{
		`echo "unterminated`,
		"ls -la $DIR",
		`"$HOME/bin/x" --flag`,
		"$GIT status",
		`bash -c "$CMD"`,
		"python -c 'print(1)'",
		"git status",
		"gh pr view 42",
	}
	for _, command := range allowed {
		decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": command}))
		if err != nil {
			t.Fatal(err)
		}
		if decision.Decision != risk.DecisionAllow {
			t.Errorf("%q: decision = %#v, want allow", command, decision)
		}
	}

	denied := map[string]string{
		"git --future-global push -f origin main": "block-unrecognized-github-operations",
		"git -c alias.p='push -f' p":              "block-unrecognized-github-operations",
		"git push $OPTS origin main":              "block-github-writes, block-unrecognized-github-operations",
		"gh weird-command":                        "block-unrecognized-github-operations",
		"git push origin main":                    "block-github-writes",
		"git push -f origin main":                 "block-github-force-push, block-github-writes",
	}
	for command, rules := range denied {
		decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": command}))
		if err != nil {
			t.Fatal(err)
		}
		if decision.Decision != risk.DecisionDeny || decision.Reason != "Blocked by rule "+rules {
			t.Errorf("%q: decision = %#v, want deny by %s", command, decision, rules)
		}
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestCedarForceWithLeaseIsNotForcePush(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, githubForcePushPolicy)
	provider := newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)

	decision, err := provider.DecideHook(context.Background(), cedarHookEvent("Bash", map[string]any{"command": "git push --force-with-lease origin main"}))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Decision != risk.DecisionAllow {
		t.Fatalf("decision = %#v, want allow", decision)
	}
}

func TestCedarGitHubMCPUsesPinnedToolIDs(t *testing.T) {
	policy := `@id("allow") permit(principal, action == Kontext::Action::"ToolUse", resource);
@id("github-read-only") forbid(principal, action == Kontext::Action::"ToolUse", resource == Kontext::Tool::"github-mcp/create_issue");
@id("github-block-unrecognized") forbid(principal, action == Kontext::Action::"ToolUse", resource == Kontext::Tool::"github-mcp/unrecognized");`
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, policy)
	provider := newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)

	tests := []struct {
		name  string
		tool  string
		input map[string]any
		want  risk.Decision
	}{
		{"known read", "mcp__github__get_me", map[string]any{}, risk.DecisionAllow},
		{"known write", "mcp__github__create_issue", map[string]any{"owner": "acme", "repo": "api", "title": "bug"}, risk.DecisionDeny},
		{"broken known schema", "mcp__github__create_issue", map[string]any{"owner": "acme"}, risk.DecisionDeny},
		{"new GitHub tool", "mcp__github__future_tool", map[string]any{}, risk.DecisionDeny},
		{"custom MCP", "mcp__custom__future_tool", map[string]any{}, risk.DecisionAllow},
		{"renamed server known write", "mcp__gh-enterprise__create_issue", map[string]any{"owner": "acme", "repo": "api", "title": "bug"}, risk.DecisionDeny},
		{"renamed server known read", "mcp__gh-enterprise__get_me", map[string]any{}, risk.DecisionAllow},
		{"renamed server schema drift", "mcp__gh-enterprise__push_files", map[string]any{"owner": "o", "repo": "r", "branch": "main", "files": []any{}}, risk.DecisionDeny},
		{"default server schema drift", "mcp__github__push_files", map[string]any{"owner": "o", "repo": "r", "branch": "main", "files": []any{}}, risk.DecisionDeny},
		{"unrelated server same-named tool", "mcp__linear__create_issue", map[string]any{"teamId": "T1", "title": "bug"}, risk.DecisionAllow},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision, err := provider.DecideHook(context.Background(), cedarHookEvent(test.tool, test.input))
			if err != nil {
				t.Fatal(err)
			}
			if decision.Decision != test.want {
				t.Fatalf("decision = %#v, want %q", decision, test.want)
			}
		})
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
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"Read");`)
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
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, `@id("permit-read") permit(principal, action, resource == Kontext::Tool::"Read");`)
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

func codexHookEvent(tool string, input map[string]any) risk.HookEvent {
	return risk.HookEvent{SessionID: "codex-session-1", Agent: "codex", HookEventName: "PreToolUse", ToolName: tool, ToolInput: input}
}

// TestCedarForcePushProbeCorpusCodex runs the probe corpus the way Codex
// delivers it: argv arrays under its shell tool names, usually wrapped in
// bash -lc and sometimes as plain argv. Every bypass must deny exactly as it
// does for Claude Code.
func TestCedarForcePushProbeCorpusCodex(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, githubForcePushPolicy)
	provider := newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)
	shellTools := []string{"shell", "unified_exec", "exec_command", "local_shell"}

	denied := []map[string]any{
		{"command": []any{"bash", "-lc", "git push --force origin main"}, "workdir": "/tmp/repo"},
		{"command": []any{"bash", "-lc", "git push -f origin main"}},
		{"command": []any{"/bin/zsh", "-lc", "git status; git push -f origin main"}},
		{"command": []any{"sh", "-c", "exec git push -f origin main"}},
		{"command": []any{"bash", "-lc", "bash -c 'git push -f origin main'"}},
		{"command": []any{"bash", "-lc", "git push origin +HEAD:main"}},
		{"command": []any{"git", "push", "--force", "origin", "main"}},
		{"command": []any{"git", "push", "-fu", "origin", "main"}},
		{"command": []any{"git", "push", "origin", "+main"}},
		{"command": []any{"timeout", "30", "git", "push", "-f", "origin", "main"}},
		{"command": []any{"git", "-c", "alias.x=y", "push", "-f", "origin", "main"}},
		{"command": "git push -f origin main"},
	}
	for _, tool := range shellTools {
		for _, input := range denied {
			decision, err := provider.DecideHook(context.Background(), codexHookEvent(tool, input))
			if err != nil {
				t.Fatal(err)
			}
			if decision.Decision != risk.DecisionDeny || decision.Reason != "Blocked by rule github-block-force-push" {
				t.Errorf("%s %v: decision = %#v, want deny by the force-push rule", tool, input["command"], decision)
			}
			if decision.Cedar.ToolID != cedareval.ToolShellV2 {
				t.Errorf("%s %v: tool id = %q, want shell", tool, input["command"], decision.Cedar.ToolID)
			}
		}
	}

	allowed := []map[string]any{
		{"command": []any{"bash", "-lc", "git status"}},
		{"command": []any{"bash", "-lc", "git push --force-with-lease origin main"}},
		{"command": []any{"git", "push", "origin", "main"}},
		{"command": []any{"git", "push", "--force-with-lease", "origin", "main"}},
		{"command": []any{"git", "commit", "-m", "force push origin main later"}},
		{"command": []any{"gh", "pr", "view", "42"}},
		{"command": []any{"bash", "-lc", "command -v git"}},
	}
	for _, tool := range shellTools {
		for _, input := range allowed {
			decision, err := provider.DecideHook(context.Background(), codexHookEvent(tool, input))
			if err != nil {
				t.Fatal(err)
			}
			if decision.Decision != risk.DecisionAllow {
				t.Errorf("%s %v: decision = %#v, want allow", tool, input["command"], decision)
			}
		}
	}
}

// TestCedarCodexNonShellAndEmptyInputs keeps Codex's other shapes out of the
// engine-error path: apply_patch is never a shell however its input looks, a
// missing tool_input evaluates as an empty object, and GitHub MCP tools
// resolve to the same pinned ids as under Claude Code.
func TestCedarCodexNonShellAndEmptyInputs(t *testing.T) {
	deployment := cedarTestDeployment(t, cedareval.RolloutModeEnforce, githubForcePushPolicy)
	provider := newCedarPolicyProvider(staticHookPolicy{}, staticCedarSnapshots{snapshot: cedarpolicy.Snapshot{Deployment: &deployment, LastKnownGood: &deployment, State: cedarpolicy.StateSuccess}}, CedarEnforcementRemote)

	patch, err := provider.DecideHook(context.Background(), codexHookEvent("apply_patch", map[string]any{"command": "git push -f origin main", "patch": "*** Begin Patch"}))
	if err != nil {
		t.Fatal(err)
	}
	if patch.Decision != risk.DecisionAllow || patch.Cedar.ToolID != "apply_patch" || patch.Cedar.Shell != nil {
		t.Fatalf("apply_patch decision = %#v, want allow as a non-shell tool", patch)
	}

	for _, tool := range []string{"shell", "view_image", "Read"} {
		decision, err := provider.DecideHook(context.Background(), codexHookEvent(tool, nil))
		if err != nil {
			t.Fatal(err)
		}
		if decision.Decision != risk.DecisionAllow || decision.Cedar.EngineErrorCount != 0 || decision.Cedar.Mapping.DerivedCedarAction != cedareval.DerivedCedarActionAllow {
			t.Fatalf("%s with nil input: decision = %#v, want policy-decided allow without engine error", tool, decision)
		}
	}

	mcp, err := provider.DecideHook(context.Background(), codexHookEvent("mcp__github__get_me", map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if mcp.Cedar.ToolID != "github-mcp/get_me" {
		t.Fatalf("Cedar evidence = %#v, want pinned GitHub tool id", mcp.Cedar)
	}
}
