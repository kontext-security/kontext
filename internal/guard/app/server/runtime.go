package server

import (
	"context"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/cedareval"
	guardhookruntime "github.com/kontext-security/kontext-cli/internal/guard/hookruntime"
	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/hook"
	"github.com/kontext-security/kontext-cli/internal/runtimecore"
)

type guardHookRuntime struct {
	store            *sqlite.Store
	policy           PolicyProvider
	currentSessionID string
	mode             string
	classifier       *riskclassifier.Classifier
}

func newGuardHookRuntime(store *sqlite.Store, policy PolicyProvider, currentSessionID, mode string, classifier *riskclassifier.Classifier) guardHookRuntime {
	return guardHookRuntime{
		store:            store,
		policy:           policy,
		currentSessionID: currentSessionID,
		mode:             mode,
		classifier:       classifier,
	}
}

func (r guardHookRuntime) OpenSession(ctx context.Context, session runtimecore.Session) (runtimecore.Session, error) {
	source := string(session.Source)
	if source == "" {
		source = string(runtimecore.SessionSourceDaemonObserved)
	}
	record, err := r.store.OpenSessionWithMode(ctx, session.ID, session.Agent, session.CWD, source, session.ExternalID, r.modeForSession(session.ID))
	if err != nil {
		return runtimecore.Session{}, err
	}
	return runtimecore.Session{
		ID:         record.ID,
		Agent:      record.Agent,
		CWD:        record.CWD,
		Source:     runtimecore.SessionSource(record.Source),
		ExternalID: record.ExternalID,
	}, nil
}

func (r guardHookRuntime) CloseSession(ctx context.Context, sessionID string) error {
	return r.store.CloseSession(ctx, sessionID)
}

func (r guardHookRuntime) EnsureSessionForEvent(ctx context.Context, event hook.Event) (hook.Event, error) {
	session, err := r.store.EnsureObservedSessionWithMode(ctx, event.SessionID, event.Agent, event.CWD, r.modeForSession(event.SessionID))
	if err != nil {
		return hook.Event{}, err
	}
	event.SessionID = session.ID
	if event.Agent == "" {
		event.Agent = session.Agent
	}
	return event, nil
}

func (r guardHookRuntime) modeForSession(sessionID string) string {
	if sessionID == "" {
		return ""
	}
	if r.currentSessionID != "" && sessionID != r.currentSessionID {
		return ""
	}
	return r.mode
}

func (r guardHookRuntime) EvaluateHook(ctx context.Context, event hook.Event) (hook.Result, error) {
	decision, err := r.decideAndRecord(ctx, riskEventFromHookEvent(event))
	if err != nil {
		return hook.Result{}, err
	}
	return hookResultFromRiskDecision(decision), nil
}

func (r guardHookRuntime) IngestEvent(ctx context.Context, event hook.Event) (hook.Result, error) {
	decision, err := r.decideAndRecord(ctx, riskEventFromHookEvent(event))
	if err != nil {
		return hook.Result{}, err
	}
	return hookResultFromRiskDecision(decision), nil
}

func (r guardHookRuntime) decideAndRecord(ctx context.Context, event risk.HookEvent) (risk.RiskDecision, error) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	r.observePrompt(event)
	decision, err := r.policy.DecideHook(ctx, event)
	if err != nil {
		return risk.RiskDecision{}, err
	}
	// Annotate here, between the final decision and the write. Here is the only
	// place that sees Cedar's actual answer, and the only place every path —
	// observe, enforce, managed — passes through, so one call site covers them
	// all. It is also what keeps the classifier advisory: the decision is
	// already settled and annotate may write nothing but its Classifier field.
	r.annotate(ctx, event, &decision)
	record, err := r.store.SaveDecision(ctx, event, decision)
	if err != nil {
		return risk.RiskDecision{}, err
	}
	decision.EventID = record.ID
	r.recordAnnotation(ctx, record.ID, event, decision)
	return decision, nil
}

// annotate attaches the advisory risk verdict to a settled decision. Both
// models run for every outcome, denies included: a deny is precisely the case
// where knowing whether the models agreed with the policy is worth the most,
// and the annotation cannot change what has already been decided.
func (r guardHookRuntime) annotate(ctx context.Context, event risk.HookEvent, decision *risk.RiskDecision) {
	if r.classifier == nil || event.HookEventName != hook.HookPreToolUse.String() {
		return
	}
	command := risk.CommandFromInput(event.ToolInput)
	if strings.TrimSpace(command) == "" {
		return
	}
	verdicts := r.classifier.Classify(ctx, event.SessionID, command)
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
		annotation.LLMRaw = verdicts.LLM.Raw
		annotation.LLM = &risk.ClassifierLLM{
			Verdict:    verdicts.LLM.Verdict,
			Model:      verdicts.LLM.Model,
			DurationMs: verdicts.LLM.DurationMs,
			Cached:     verdicts.LLM.Cached,
		}
	}
	decision.Classifier = annotation
}

// recordAnnotation persists the local verdict row. The annotation already rode
// along with the decision into the action row (and its receipt), so this is the
// local-only half: the redacted command, the agent task, and the feedback
// columns the dashboard writes later.
func (r guardHookRuntime) recordAnnotation(ctx context.Context, actionID string, event risk.HookEvent, decision risk.RiskDecision) {
	annotation := decision.Classifier
	if annotation == nil || annotation.SVM == nil || actionID == "" {
		return
	}
	record := riskclassifier.Record{
		ActionID:         actionID,
		SessionID:        event.SessionID,
		ToolUseID:        event.ToolUseID,
		Agent:            event.Agent,
		Command:          annotation.Command,
		CommandHash:      annotation.CommandHash,
		CommandTruncated: annotation.CommandTruncated,
		AgentTask:        annotation.AgentTask,
		LLMError:         annotation.LLMError,
		SVM: &riskclassifier.SVMVerdict{
			Verdict:      annotation.SVM.Verdict,
			Score:        annotation.SVM.Score,
			Threshold:    annotation.SVM.Threshold,
			ModelVersion: annotation.SVM.ModelVersion,
		},
	}
	if annotation.LLM != nil {
		record.LLM = &riskclassifier.LLMVerdict{
			Verdict:    annotation.LLM.Verdict,
			Model:      annotation.LLM.Model,
			Raw:        annotation.LLMRaw,
			PromptID:   annotation.LLMPromptID,
			DurationMs: annotation.LLM.DurationMs,
			Cached:     annotation.LLM.Cached,
		}
	}
	// Advisory data: a failed write must not fail the tool call.
	_, _ = r.store.SaveClassifierVerdict(ctx, record)
}

// observePrompt keeps the session's latest user prompt so classifier records
// carry the agent task that motivated the command.
func (r guardHookRuntime) observePrompt(event risk.HookEvent) {
	if r.classifier == nil || event.HookEventName != "UserPromptSubmit" {
		return
	}
	prompt, _ := event.ToolInput["prompt"].(string)
	r.classifier.RecordPrompt(event.SessionID, prompt)
}

func riskEventFromHookEvent(event hook.Event) risk.HookEvent {
	return risk.HookEvent{
		SessionID:     event.SessionID,
		Agent:         event.Agent,
		HookEventName: event.HookName.String(),
		ToolName:      event.ToolName,
		ToolInput:     event.ToolInput,
		ToolResponse:  event.ToolResponse,
		ToolUseID:     event.ToolUseID,
		CWD:           event.CWD,
	}
}

func hookEventFromRiskEvent(event risk.HookEvent) hook.Event {
	return hook.Event{
		SessionID:    event.SessionID,
		Agent:        event.Agent,
		HookName:     hook.HookName(event.HookEventName),
		ToolName:     event.ToolName,
		ToolInput:    event.ToolInput,
		ToolResponse: event.ToolResponse,
		ToolUseID:    event.ToolUseID,
		CWD:          event.CWD,
	}
}

func hookResultFromRiskDecision(decision risk.RiskDecision) hook.Result {
	result := hook.Result{
		Decision:   hook.Decision(decision.Decision),
		Reason:     decision.Reason,
		ReasonCode: decision.ReasonCode,
		EventID:    decision.EventID,
	}
	// A Cedar decision applied under an enforce rollout is authoritative: mark
	// the result so hook edges (which otherwise downgrade every decision to
	// observe) pass the decision through. The client-side transform still owns
	// the final posture per runtime mode.
	if decision.Cedar != nil && decision.Cedar.AppliedRolloutMode == cedareval.RolloutModeEnforce {
		result.Mode = string(guardhookruntime.ModeEnforce)
	}
	return hook.WithMetadata(result, decision)
}

func riskDecisionFromHookResult(result hook.Result) risk.RiskDecision {
	if decision, ok := result.Metadata().(risk.RiskDecision); ok {
		return decision
	}
	return risk.RiskDecision{
		Decision:   risk.Decision(result.Decision),
		Reason:     result.Reason,
		ReasonCode: result.ReasonCode,
		EventID:    result.EventID,
	}
}
