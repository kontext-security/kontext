package server

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/kontext-security/kontext-cli/internal/guard/judge"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/riskclassifier"
)

type PolicyProvider interface {
	DecideHook(context.Context, risk.HookEvent) (risk.RiskDecision, error)
}

type RiskPolicyProvider struct {
	judge      judge.Judge
	classifier *riskclassifier.Classifier
	Classifier *riskclassifier.Classifier
}

func NewRiskPolicyProvider() RiskPolicyProvider {
	return NewRiskPolicyProviderWithJudge(nil)
}

func NewRiskPolicyProviderWithJudge(localJudge judge.Judge) RiskPolicyProvider {
	return RiskPolicyProvider{judge: localJudge}
}

func (p RiskPolicyProvider) DecideHook(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	if event.HookEventName != "PreToolUse" {
		return p.asyncTelemetryDecision(event), nil
	}
	riskEvent := risk.NormalizeHookEvent(event)
	// The decision is settled first, in one place, and only then annotated.
	// Structuring it this way is what makes the classifier advisory: annotate
	// receives a finished decision and may write nothing but its Classifier
	// field, so no verdict can reach an allow/deny outcome.
	decision := p.decide(ctx, event, riskEvent)
	p.annotate(ctx, event, &decision)
	return decision, nil
}

// decide runs the local chain, which is itself advisory: Cedar (the
// cedarPolicyProvider wrapping this chain) is the only engine that decides.
// Judge analysis is recorded as risk signals on the decision fact; the chain's
// own outcome is always allow.
func (p RiskPolicyProvider) decide(ctx context.Context, event risk.HookEvent, riskEvent risk.RiskEvent) risk.RiskDecision {
	if p.judge == nil {
		return advisoryDecision(riskEvent)
	}
	result, err := p.judge.Decide(ctx, judgeInputFromRiskEvent(event, riskEvent))
	if err != nil {
		return judgeFailOpenDecision(riskEvent, p.judge, err)
	}
	return judgeAdvisoryDecision(riskEvent, result)
}

// annotate attaches the advisory risk verdict to an already-decided action. The
// guardrail LLM is skipped when this chain itself denied, since there is nothing
// an advisory second opinion can add that is worth the inference; the SVM still
// runs because it costs microseconds and a denied command is exactly the kind of
// example worth having a score for.
//
// Note this chain is advisory, so a Cedar deny is not visible here — the
// guardrail will run for commands Cedar goes on to deny. That is an efficiency
// cost only; annotating cannot affect any decision either way.
func (p RiskPolicyProvider) annotate(ctx context.Context, event risk.HookEvent, decision *risk.RiskDecision) {
	if p.classifier == nil {
		return
	}
	command := risk.CommandFromInput(event.ToolInput)
	if strings.TrimSpace(command) == "" {
		return
	}
	allowLLM := decision.Decision != risk.DecisionDeny
	verdicts := p.classifier.Classify(ctx, event.SessionID, command, allowLLM)
	if verdicts.SVM == nil {
		return
	}
	annotation := &risk.ClassifierAnnotation{
		LLMError:         verdicts.LLMError,
		Command:          verdicts.Command,
		CommandHash:      verdicts.CommandHash,
		CommandTruncated: verdicts.CommandTruncated,
		AgentTask:        verdicts.AgentTask,
		SVM: &risk.ClassifierSVM{
			Verdict:      verdicts.SVM.Verdict,
			Score:        verdicts.SVM.Score,
			Threshold:    verdicts.SVM.Threshold,
			ModelVersion: verdicts.SVM.ModelVersion,
		},
	}
	if verdicts.LLM != nil {
		annotation.LLMPromptID = verdicts.LLM.PromptID
		annotation.LLM = &risk.ClassifierLLM{
			Verdict:    verdicts.LLM.Verdict,
			Model:      verdicts.LLM.Model,
			DurationMs: verdicts.LLM.DurationMs,
			Cached:     verdicts.LLM.Cached,
		}
	}
	decision.Classifier = annotation
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

// advisoryDecision records the observation without deciding: no judge is
// wired, so there is no analysis to attach. Cedar alone decides.
func advisoryDecision(riskEvent risk.RiskEvent) risk.RiskDecision {
	riskEvent.Decision = risk.DecisionAllow
	riskEvent.ReasonCode = risk.DecisionStageAdvisory
	riskEvent.DecisionStage = risk.DecisionStageAdvisory
	return risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "observed; no local analysis wired",
		ReasonCode: risk.DecisionStageAdvisory,
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
	// The judge never controls execution here, but preserve its verdict as
	// analysis so the dashboard can distinguish an advisory allow from deny.
	riskEvent.DecisionStage = reasonCode
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
