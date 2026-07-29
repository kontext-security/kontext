package server

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/githubpolicy"
	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	guardpolicy "github.com/kontext-security/kontext-cli/internal/guard/policy"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext-cli/internal/hubspotpolicy"
	"github.com/kontext-security/kontext-cli/internal/providerpolicy"
)

// ProviderPolicyBinding wires one provider's synced policy into the decision
// path: a snapshot source plus a classifier turning hook events into that
// provider's canonical policy requests (subject fields are filled in by the
// evaluator).
type ProviderPolicyBinding struct {
	Provider  string
	Snapshots providerpolicy.SnapshotProvider
	Classify  func(event risk.HookEvent) []providerpolicy.Request
}

// GithubPolicyBinding binds the GitHub classifier to a snapshot source.
func GithubPolicyBinding(snapshots providerpolicy.SnapshotProvider) ProviderPolicyBinding {
	return ProviderPolicyBinding{
		Provider:  "github",
		Snapshots: snapshots,
		Classify: func(event risk.HookEvent) []providerpolicy.Request {
			actions := githubpolicy.ClassifyProviderActionsWithCWD(event.ToolName, event.ToolInput, event.CWD, func(cwd string) githubpolicy.GitContext {
				return githubpolicy.GitContextFromCWD(cwd)
			})
			requests := make([]providerpolicy.Request, 0, len(actions))
			for _, action := range actions {
				requests = append(requests, providerpolicy.Request{
					Action:      action.Action,
					Resource:    action.Resource,
					BranchOrRef: action.BranchOrRef,
				})
			}
			return requests
		},
	}
}

// HubspotPolicyBinding binds the HubSpot classifier to a snapshot source. The
// Cowork connector registry is resolved lazily per event from the hook cwd.
func HubspotPolicyBinding(snapshots providerpolicy.SnapshotProvider) ProviderPolicyBinding {
	return ProviderPolicyBinding{
		Provider:  "hubspot",
		Snapshots: snapshots,
		Classify: func(event risk.HookEvent) []providerpolicy.Request {
			actions := hubspotpolicy.ClassifyProviderActions(event.ToolName, event.ToolInput, hubspotpolicy.ConnectorResolverForCWD(event.CWD))
			requests := make([]providerpolicy.Request, 0, len(actions))
			for _, action := range actions {
				requests = append(requests, providerpolicy.Request{
					Action:   action.Action,
					Resource: action.Resource,
				})
			}
			return requests
		},
	}
}

type PolicyProvider interface {
	DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error)
}

type PolicyConfigProvider interface {
	ActivePolicyConfig(context.Context) (guardpolicy.Config, error)
}

type RiskPolicyProvider struct {
	judge judge.Judge
	// guardrail, when set, replaces the JSON judge as the probabilistic layer
	// for shell commands (sync placement). Its verdict is carried on the
	// decision so the feedback log does not pay for a second inference.
	guardrail    *riskclassifier.Guardrail
	policyEngine guardpolicy.Engine
	policyConfig PolicyConfigProvider
	// providerPolicies are the synced-policy bindings evaluated per event.
	providerPolicies []ProviderPolicyBinding
	// endpointID is this managed endpoint's installation ("ins_…") id, used as
	// the endpoint-layer subject when evaluating synced provider policy.
	endpointID string
}

type RiskPolicyProviderOptions struct {
	Judge                judge.Judge
	PolicyEngine         guardpolicy.Engine
	PolicyConfig         guardpolicy.Config
	PolicyConfigProvider PolicyConfigProvider
	ProviderPolicies     []ProviderPolicyBinding
	EndpointID           string
}

type staticPolicyConfigProvider struct {
	config guardpolicy.Config
}

func (p staticPolicyConfigProvider) ActivePolicyConfig(context.Context) (guardpolicy.Config, error) {
	return p.config, nil
}

func NewRiskPolicyProvider() RiskPolicyProvider {
	return NewRiskPolicyProviderWithJudge(nil)
}

func NewRiskPolicyProviderWithJudge(localJudge judge.Judge) RiskPolicyProvider {
	return NewRiskPolicyProviderWithOptions(RiskPolicyProviderOptions{
		Judge: localJudge,
	})
}

func NewRiskPolicyProviderWithOptions(opts RiskPolicyProviderOptions) RiskPolicyProvider {
	configProvider := opts.PolicyConfigProvider
	if configProvider == nil {
		configProvider = staticPolicyConfigProvider{config: opts.PolicyConfig}
	}
	return RiskPolicyProvider{
		judge:            opts.Judge,
		policyEngine:     opts.PolicyEngine,
		policyConfig:     configProvider,
		providerPolicies: opts.ProviderPolicies,
		endpointID:       opts.EndpointID,
	}
}

func (p RiskPolicyProvider) DecideHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	if event.HookEventName != "PreToolUse" {
		return p.asyncTelemetryDecision(event), nil
	}
	riskEvent := risk.NormalizeHookEvent(event)
	policyResult := p.policyEngine.Evaluate(riskEvent, p.activePolicyConfig(ctx))
	applyPolicyMetadata(&riskEvent, policyResult)
	// Local layering: deterministic guardrails > synced provider policy >
	// probabilistic signals. A guardrail deny stands regardless of what the
	// synced policy would have said; a synced policy (when enforcing)
	// pre-empts the judge.
	providerEvaluations, enforcing := p.evaluateProviderPolicies(event)
	if policyResult.Decision == guardpolicy.DecisionDeny {
		return withProviderPolicy(deterministicDenyDecision(riskEvent, policyResult), providerEvaluations), nil
	}
	if len(enforcing) > 0 {
		return withProviderPolicy(providerPolicyDecision(riskEvent, enforcing), providerEvaluations), nil
	}
	// The guardrail supersedes the JSON judge when configured: one local LLM,
	// prompted for shell-command risk. It only speaks to shell commands, so
	// path/skill/MCP calls fall through to the deterministic allow rather than
	// being asked of a classifier trained on a different question.
	if p.guardrail != nil {
		command := risk.CommandFromInput(event.ToolInput)
		if strings.TrimSpace(command) == "" {
			return withProviderPolicy(deterministicAllowDecision(riskEvent, policyResult), providerEvaluations), nil
		}
		verdict, err := p.guardrail.Classify(ctx, command)
		if err != nil {
			decision := guardrailFailOpenDecision(riskEvent, p.guardrail, err)
			return withProviderPolicy(decision, providerEvaluations), nil
		}
		return withProviderPolicy(guardrailDecision(riskEvent, verdict), providerEvaluations), nil
	}
	if p.judge == nil {
		return withProviderPolicy(deterministicAllowDecision(riskEvent, policyResult), providerEvaluations), nil
	}

	result, err := p.judge.Decide(ctx, judgeInputFromRiskEvent(event, riskEvent))
	if err != nil {
		return withProviderPolicy(judgeFailOpenDecision(riskEvent, p.judge, err), providerEvaluations), nil
	}
	return withProviderPolicy(judgeDecision(riskEvent, result), providerEvaluations), nil
}

// guardrailDecision turns a RISKY/SAFE verdict into a risk decision, carrying
// the verdict itself so the feedback record reuses this inference.
func guardrailDecision(riskEvent risk.RiskEvent, verdict riskclassifier.LLMVerdict) risk.RiskDecision {
	decision := risk.DecisionAllow
	reasonCode := "guardrail_allow"
	reason := "local guardrail rated the command safe"
	if verdict.Verdict == riskclassifier.VerdictRisky {
		decision = risk.DecisionDeny
		reasonCode = "guardrail_deny"
		reason = "local guardrail rated the command risky"
	}
	duration := verdict.DurationMs
	riskEvent.Decision = decision
	riskEvent.ReasonCode = reasonCode
	riskEvent.DecisionStage = reasonCode
	riskEvent.GuardID = "local_guardrail"
	riskEvent.JudgeRuntime = judge.DefaultLlamaServerRuntime
	riskEvent.JudgeModel = verdict.Model
	riskEvent.JudgeDurationMs = &duration
	return risk.RiskDecision{
		Decision:   decision,
		Reason:     reason,
		ReasonCode: reasonCode,
		GuardID:    "local_guardrail",
		RiskEvent:  riskEvent,
		Guardrail: &risk.LLMVerdict{
			Verdict:    verdict.Verdict,
			Raw:        verdict.Raw,
			Model:      verdict.Model,
			PromptID:   verdict.PromptID,
			DurationMs: verdict.DurationMs,
		},
	}
}

// guardrailFailOpenDecision mirrors the judge's fail-open contract: an
// unavailable or unparseable local model allows the call and records why.
func guardrailFailOpenDecision(riskEvent risk.RiskEvent, guardrail *riskclassifier.Guardrail, err error) risk.RiskDecision {
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = "guardrail_unavailable_allow"
	riskEvent.DecisionStage = "guardrail_unavailable_allow"
	riskEvent.JudgeRuntime = judge.DefaultLlamaServerRuntime
	riskEvent.JudgeModel = guardrail.Model()
	riskEvent.JudgeFailureKind = "unavailable"
	return risk.RiskDecision{
		Decision:     risk.DecisionAllow,
		Reason:       "local guardrail unavailable; allowing by fail-open policy",
		ReasonCode:   "guardrail_unavailable_allow",
		RiskEvent:    riskEvent,
		GuardrailErr: err.Error(),
	}
}

// evaluateProviderPolicies classifies the event through every bound
// provider's classifier and evaluates the classified actions against that
// provider's synced snapshot. The managed endpoint's trusted identity is the
// service account + installation — Claude hook payloads are not trusted human
// identity — so requests carry no Kontext user/application subject and
// user/agent-layer rules cannot match their subject (the evaluation flags
// this via SubjectsResolved). The endpoint's own installation id IS known and
// trusted, so it is supplied as the endpoint-layer subject; endpoint-scoped
// rules are how device policy is enforced on this path.
//
// The second result is the first provider whose snapshot explicitly directs
// enforcement AND produced evaluations for this event; empty otherwise. In
// the observer pilot every snapshot is observe-mode, so it is always empty.
func (p RiskPolicyProvider) evaluateProviderPolicies(event risk.HookEvent) ([]risk.ProviderPolicyEvaluations, []risk.ProviderPolicyEvaluations) {
	var all []risk.ProviderPolicyEvaluations
	var enforcing []risk.ProviderPolicyEvaluations
	for _, binding := range p.providerPolicies {
		if binding.Snapshots == nil || binding.Classify == nil {
			continue
		}
		snapshot, status, ok := binding.Snapshots.CurrentSnapshot()
		if !ok || len(snapshot.Rules) == 0 {
			continue
		}
		requests := binding.Classify(event)
		if len(requests) == 0 {
			continue
		}
		evaluations := make([]providerpolicy.Evaluation, 0, len(requests))
		for _, request := range requests {
			request.EndpointID = p.endpointID
			if evaluation, ok := providerpolicy.Evaluate(snapshot, status, request); ok {
				evaluations = append(evaluations, evaluation)
			}
		}
		if len(evaluations) == 0 {
			continue
		}
		group := risk.ProviderPolicyEvaluations{Provider: binding.Provider, Evaluations: evaluations}
		all = append(all, group)
		if snapshot.Enforce() {
			enforcing = append(enforcing, group)
		}
	}
	return all, enforcing
}

func withProviderPolicy(decision risk.RiskDecision, evaluations []risk.ProviderPolicyEvaluations) risk.RiskDecision {
	decision.ProviderPolicy = evaluations
	return decision
}

// providerPolicyDecision is the enforce-mode path, reserved for after the
// observer pilot: the synced policy outranks probabilistic signals, so its
// verdict decides instead of the judge. ANY enforcing provider's denied
// action denies the event — an event that classifies under two enforcing
// providers must not slip through because the first one allowed it.
func providerPolicyDecision(riskEvent risk.RiskEvent, enforcing []risk.ProviderPolicyEvaluations) risk.RiskDecision {
	for _, provider := range enforcing {
		for _, evaluation := range provider.Evaluations {
			if evaluation.Result == providerpolicy.EffectDeny {
				riskEvent.Decision = risk.DecisionDeny
				riskEvent.ReasonCode = evaluation.ReasonCode
				riskEvent.DecisionStage = provider.Provider + "_policy_deny"
				return risk.RiskDecision{
					Decision:   risk.DecisionDeny,
					Reason:     evaluation.Reason,
					ReasonCode: evaluation.ReasonCode,
					GuardID:    evaluation.DecidingRuleID,
					RiskEvent:  riskEvent,
				}
			}
		}
	}
	first := enforcing[0]
	allowed := first.Evaluations[0]
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = allowed.ReasonCode
	riskEvent.DecisionStage = first.Provider + "_policy_allow"
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     allowed.Reason,
		ReasonCode: allowed.ReasonCode,
		GuardID:    allowed.DecidingRuleID,
		RiskEvent:  riskEvent,
	}
}

func (p RiskPolicyProvider) asyncTelemetryDecision(event risk.HookEvent) risk.RiskDecision {
	riskEvent := risk.NormalizeHookEvent(event)
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = "async_telemetry"
	riskEvent.DecisionStage = "async_telemetry"
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "async telemetry event recorded",
		ReasonCode: "async_telemetry",
		RiskEvent:  riskEvent,
	}
}

func deterministicDenyDecision(riskEvent risk.RiskEvent, policyResult guardpolicy.Result) risk.RiskDecision {
	riskEvent.Decision = risk.DecisionDeny
	riskEvent.ReasonCode = policyResult.ReasonCode
	riskEvent.GuardID = policyResult.RuleID
	riskEvent.DecisionStage = risk.DecisionStageDeterministicDeny
	return risk.RiskDecision{
		Decision:   risk.DecisionDeny,
		Reason:     policyResult.Reason,
		ReasonCode: policyResult.ReasonCode,
		GuardID:    policyResult.RuleID,
		RiskEvent:  riskEvent,
	}
}

func deterministicAllowDecision(riskEvent risk.RiskEvent, policyResult guardpolicy.Result) risk.RiskDecision {
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = policyResult.ReasonCode
	riskEvent.DecisionStage = "deterministic_allow"
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     policyResult.Reason,
		ReasonCode: policyResult.ReasonCode,
		RiskEvent:  riskEvent,
	}
}

func judgeFailOpenDecision(riskEvent risk.RiskEvent, localJudge judge.Judge, err error) risk.RiskDecision {
	failureKind := judge.FailureKind(err)
	metadata := judgeMetadata(localJudge)
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = "judge_unavailable_allow"
	riskEvent.DecisionStage = risk.DecisionStageJudgeFailOpen
	riskEvent.JudgeRuntime = metadata.Runtime
	riskEvent.JudgeModel = metadata.Model
	riskEvent.JudgeFailureKind = failureKind
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "local judge unavailable; allowing by fail-open policy",
		ReasonCode: "judge_unavailable_allow",
		RiskEvent:  riskEvent,
	}
}

func judgeDecision(riskEvent risk.RiskEvent, result judge.Result) risk.RiskDecision {
	decision := risk.DecisionAllow
	reasonCode := risk.DecisionStageJudgeAllow
	if result.Output.Decision == judge.DecisionDeny {
		decision = risk.DecisionDeny
		reasonCode = risk.DecisionStageJudgeDeny
	}
	duration := result.Metadata.DurationMs
	riskEvent.Decision = decision
	riskEvent.ReasonCode = reasonCode
	riskEvent.DecisionStage = reasonCode
	riskEvent.GuardID = "local_llm_judge"
	riskEvent.JudgeRuntime = result.Metadata.Runtime
	riskEvent.JudgeModel = result.Metadata.Model
	riskEvent.JudgeDurationMs = &duration
	riskEvent.JudgeRiskLevel = string(result.Output.RiskLevel)
	riskEvent.JudgeCategories = result.Output.Categories

	return risk.RiskDecision{
		Decision:   decision,
		Reason:     result.Output.Reason,
		ReasonCode: reasonCode,
		GuardID:    "local_llm_judge",
		RiskEvent:  riskEvent,
	}
}

func (p RiskPolicyProvider) activePolicyConfig(ctx context.Context) guardpolicy.Config {
	if p.policyConfig == nil {
		return guardpolicy.DefaultConfig()
	}
	config, err := p.policyConfig.ActivePolicyConfig(ctx)
	if err != nil {
		return guardpolicy.DefaultConfig()
	}
	if err := config.Validate(); err != nil {
		return guardpolicy.DefaultConfig()
	}
	return config
}

func applyPolicyMetadata(event *risk.RiskEvent, result guardpolicy.Result) {
	event.PolicyVersion = result.PolicyVersion
	event.PolicyHash = result.PolicyHash
	event.PolicyProfile = string(result.Profile)
	event.PolicyRulePack = result.RulePack
	if !result.Matched {
		return
	}
	event.PolicyRuleID = result.RuleID
	event.PolicyRuleCategory = string(result.Category)
	event.PolicySignals = result.MatchedSignals
}

func judgeInputFromRiskEvent(event risk.HookEvent, riskEvent risk.RiskEvent) judge.Input {
	toolInput := judge.ToolInput{
		Command: riskEvent.CommandSummary,
		Path:    pathClassForJudge(event.ToolInput, riskEvent.PathClass),
	}
	if toolInput.Command == "" {
		switch {
		case toolInput.Path != "":
			toolInput.Request = sanitizedPathRequest(event.ToolName, toolInput.Path)
		case strings.EqualFold(event.ToolName, "Skill"):
			toolInput.Request = skillRequest(event.ToolInput)
		default:
			toolInput.Request = riskEvent.RequestSummary
		}
	}
	return judge.Input{
		ToolName:           event.ToolName,
		ExplicitUserIntent: riskEvent.ExplicitUserIntent,
		ToolInput:          toolInput,
	}
}

func sanitizedPathRequest(toolName, pathClass string) string {
	action := strings.TrimSpace(toolName)
	if action == "" {
		action = "Tool"
	}
	if isCredentialPathClass(pathClass) {
		return action + " credential_path " + pathClass
	}
	return action + " " + pathClass
}

func isCredentialPathClass(pathClass string) bool {
	switch pathClass {
	case "credential_file", "env_file", "cloud_credentials":
		return true
	default:
		return false
	}
}

func skillRequest(input map[string]any) string {
	name, _ := input["skill"].(string)
	name = strings.TrimSpace(name)
	if name == "" {
		return "Skill"
	}
	return "Skill " + name
}

func pathClassForJudge(input map[string]any, normalizedClass string) string {
	if normalizedClass != "" {
		return normalizedClass
	}
	for _, key := range []string{"file_path", "path", "filename"} {
		if value, ok := input[key].(string); ok {
			if value != "" {
				return judgePathClass(value)
			}
		}
	}
	return ""
}

func judgePathClass(path string) string {
	clean := strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	base := filepath.Base(clean)
	switch base {
	case ".env", ".npmrc", ".pypirc", ".netrc":
		return "env_file"
	}
	if pathHasSegmentPrefix(clean, ".aws") ||
		pathHasSegmentPrefix(clean, ".gcloud") ||
		pathHasSegmentPrefix(clean, ".config/railway") {
		return "cloud_credentials"
	}
	return "project_file"
}

func pathHasSegmentPrefix(clean, prefix string) bool {
	return clean == prefix ||
		strings.HasPrefix(clean, prefix+"/") ||
		strings.Contains(clean, "/"+prefix+"/") ||
		strings.HasSuffix(clean, "/"+prefix)
}

func judgeMetadata(localJudge judge.Judge) judge.Metadata {
	if provider, ok := localJudge.(judge.MetadataProvider); ok {
		return provider.Metadata()
	}
	return judge.Metadata{}
}
