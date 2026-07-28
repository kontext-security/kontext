package server

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	guardpolicy "github.com/kontext-security/kontext-cli/internal/guard/policy"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
)

type PolicyProvider interface {
	DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error)
}

type PolicyConfigProvider interface {
	ActivePolicyConfig(context.Context) (guardpolicy.Config, error)
}

type RiskPolicyProvider struct {
	judge        judge.Judge
	policyEngine guardpolicy.Engine
	policyConfig PolicyConfigProvider
}

type RiskPolicyProviderOptions struct {
	Judge                judge.Judge
	PolicyEngine         guardpolicy.Engine
	PolicyConfig         guardpolicy.Config
	PolicyConfigProvider PolicyConfigProvider
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
		judge:        opts.Judge,
		policyEngine: opts.PolicyEngine,
		policyConfig: configProvider,
	}
}

func (p RiskPolicyProvider) DecideHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	if event.HookEventName != "PreToolUse" {
		return p.asyncTelemetryDecision(event), nil
	}
	riskEvent := risk.NormalizeHookEvent(event)
	policyResult := p.policyEngine.Evaluate(riskEvent, p.activePolicyConfig(ctx))
	applyPolicyMetadata(&riskEvent, policyResult)
	// The local chain is advisory: Cedar (the cedarPolicyProvider wrapping
	// this chain) is the only engine that decides. Guardrail matches and
	// judge analysis are recorded as risk signals on the decision fact; the
	// chain's own outcome is always allow.
	if p.judge == nil {
		return advisoryDecision(riskEvent, policyResult), nil
	}

	result, err := p.judge.Decide(ctx, judgeInputFromRiskEvent(event, riskEvent))
	if err != nil {
		return judgeFailOpenDecision(riskEvent, p.judge, err), nil
	}
	return judgeAdvisoryDecision(riskEvent, result), nil
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

// advisoryDecision records the deterministic guardrail analysis without
// deciding: matched rules survive as policy metadata and signals on the risk
// event, and the chain's outcome is always allow. Cedar alone decides.
func advisoryDecision(riskEvent risk.RiskEvent, policyResult guardpolicy.Result) risk.RiskDecision {
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = policyResult.ReasonCode
	riskEvent.GuardID = policyResult.RuleID
	riskEvent.DecisionStage = risk.DecisionStageAdvisory
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     policyResult.Reason,
		ReasonCode: policyResult.ReasonCode,
		GuardID:    policyResult.RuleID,
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

// judgeAdvisoryDecision records the judge's analysis without deciding. The
// judge's verdict survives as the reason code and risk fields on the fact's
// advisory block; the chain's outcome is always allow.
func judgeAdvisoryDecision(riskEvent risk.RiskEvent, result judge.Result) risk.RiskDecision {
	reasonCode := risk.DecisionStageJudgeAllow
	if result.Output.Decision == judge.DecisionDeny {
		reasonCode = risk.DecisionStageJudgeDeny
	}
	duration := result.Metadata.DurationMs
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = reasonCode
	riskEvent.DecisionStage = risk.DecisionStageAdvisory
	riskEvent.GuardID = "local_llm_judge"
	riskEvent.JudgeRuntime = result.Metadata.Runtime
	riskEvent.JudgeModel = result.Metadata.Model
	riskEvent.JudgeDurationMs = &duration
	riskEvent.JudgeRiskLevel = string(result.Output.RiskLevel)
	riskEvent.JudgeCategories = result.Output.Categories

	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
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
