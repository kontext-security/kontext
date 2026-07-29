package server

import (
	"context"
	"strings"
	"time"

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
	classifier       *riskclassifier.Observer
}

func newGuardHookRuntime(store *sqlite.Store, policy PolicyProvider, currentSessionID, mode string, classifier *riskclassifier.Observer) guardHookRuntime {
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
	record, err := r.store.SaveDecision(ctx, event, decision)
	if err != nil {
		return risk.RiskDecision{}, err
	}
	decision.EventID = record.ID
	r.observeCommand(event, record.ID, decision)
	return decision, nil
}

// observeCommand hands an intercepted bash command to the risk classifier.
// Observe-mode only: the verdicts are logged against the decided action for
// feedback collection and never revisit the decision above.
func (r guardHookRuntime) observeCommand(event risk.HookEvent, actionID string, decision risk.RiskDecision) {
	if r.classifier == nil || event.HookEventName != "PreToolUse" || actionID == "" {
		return
	}
	command := risk.CommandFromInput(event.ToolInput)
	if strings.TrimSpace(command) == "" {
		return
	}
	input := riskclassifier.ObserveInput{
		ActionID:  actionID,
		SessionID: event.SessionID,
		ToolUseID: event.ToolUseID,
		Agent:     event.Agent,
		Command:   command,
	}
	// Sync placement already ran the LLM for this command; hand the verdict over
	// rather than paying for a second inference.
	if decision.Guardrail != nil {
		input.LLM = &riskclassifier.LLMVerdict{
			Verdict:    decision.Guardrail.Verdict,
			Raw:        decision.Guardrail.Raw,
			Model:      decision.Guardrail.Model,
			PromptID:   decision.Guardrail.PromptID,
			DurationMs: decision.Guardrail.DurationMs,
		}
	}
	input.LLMError = decision.GuardrailErr
	r.classifier.Observe(input)
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
	return hook.WithMetadata(hook.Result{
		Decision:   hook.Decision(decision.Decision),
		Reason:     decision.Reason,
		ReasonCode: decision.ReasonCode,
		EventID:    decision.EventID,
	}, decision)
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
