package server

import (
	"context"
	"errors"
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
	// deferRecord, when non-nil, runs every store write for decision-gating
	// hooks — session upsert, annotation, decision row — off the hook
	// response path. The decision itself (Cedar) is always computed before
	// the response. Non-blocking hooks keep their synchronous writes: they
	// are already ingested behind an immediate response. The executor owns
	// lifetime (context, draining on shutdown) and reporting the job's
	// error. Nil keeps the historical synchronous behavior.
	deferRecord func(job func(context.Context) error)
}

func newGuardHookRuntime(store *sqlite.Store, policy PolicyProvider, currentSessionID, mode string, classifier *riskclassifier.Classifier, deferRecord func(job func(context.Context) error)) guardHookRuntime {
	return guardHookRuntime{
		store:            store,
		policy:           policy,
		currentSessionID: currentSessionID,
		mode:             mode,
		classifier:       classifier,
		deferRecord:      deferRecord,
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
	// A deferred-recording runtime answers decision-gating hooks without
	// touching the store, and the session upsert is a store write like any
	// other: on a cold guard.db it alone can outlive the hook client's budget.
	// The upsert rides along with the deferred decision record instead (see
	// decideAndRecord); only the store's session-ID normalization — a pure
	// function — happens here, so the decision, the classifier, and the
	// eventual rows key alike.
	if r.defersRecording(event.HookName) {
		event.SessionID = sqlite.NormalizeSessionID(event.SessionID)
		return event, nil
	}
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

// defersRecording reports whether this event's store writes run off the hook
// response path. Only decision-gating hooks defer: non-blocking hooks are
// already answered before ingestion (async ingest), so deferring their writes
// would only nest one background hop inside another.
func (r guardHookRuntime) defersRecording(hookName hook.HookName) bool {
	return r.deferRecord != nil && hookName.CanBlock()
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
	if r.defersRecording(hook.HookName(event.HookEventName)) {
		// The decision is settled; nothing after this point may change it.
		// Hand the agent its answer now and run annotation + persistence in
		// the background: classifier inference and a write into a large,
		// possibly cold guard.db both routinely outlive the hook client's
		// budget, and a hook that times out here is treated as a dead daemon
		// — fail-open in observe, fail-closed (every tool call denied) in
		// enforce.
		decision.EventID = sqlite.NewActionID()
		deferredEvent, deferredDecision := event, decision
		r.deferRecord(func(recordCtx context.Context) error {
			// The session upsert EnsureSessionForEvent skipped lands first,
			// mirroring the synchronous order: it carries the mode stamp
			// SaveDecision's own upsert lacks. Backfill, not Ensure: this
			// write can run after a SessionEnd that already closed the
			// session, and it must not reopen it.
			session, sessionErr := r.store.BackfillObservedSessionWithMode(recordCtx, deferredEvent.SessionID, deferredEvent.Agent, deferredEvent.CWD, r.modeForSession(deferredEvent.SessionID))
			if sessionErr == nil && deferredEvent.Agent == "" {
				deferredEvent.Agent = session.Agent
			}
			r.annotate(recordCtx, deferredEvent, &deferredDecision)
			record, err := r.store.SaveDecision(recordCtx, deferredEvent, deferredDecision)
			if err != nil {
				return errors.Join(sessionErr, err)
			}
			r.recordAnnotation(recordCtx, record.ID, deferredEvent, deferredDecision)
			return sessionErr
		})
		return decision, nil
	}
	r.annotate(ctx, event, &decision)
	record, err := r.store.SaveDecision(ctx, event, decision)
	if err != nil {
		return risk.RiskDecision{}, err
	}
	decision.EventID = record.ID
	r.recordAnnotation(ctx, record.ID, event, decision)
	return decision, nil
}

// annotate attaches the advisory risk verdict to a settled decision. The
// binary and optional LLM models run for every outcome, denies included: a
// deny is precisely the case where knowing whether the models agreed with the
// policy is worth the most,
// and the annotation cannot change what has already been decided. Risk types
// are further gated to binary-risky shell commands inside Classifier.Classify.
func (r guardHookRuntime) annotate(ctx context.Context, event risk.HookEvent, decision *risk.RiskDecision) {
	if r.classifier == nil || event.HookEventName != hook.HookPreToolUse.String() {
		return
	}
	command := risk.CommandFromInput(event.ToolInput)
	if strings.TrimSpace(command) == "" {
		return
	}
	verdicts := r.classifier.Classify(ctx, event.SessionID, event.ToolName, command)
	if verdicts.SVM == nil {
		return
	}
	annotation := &risk.ClassifierAnnotation{
		LLMError:         verdicts.LLMError,
		RiskTypeError:    verdicts.RiskTypeError,
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
	if verdicts.RiskTypes != nil {
		annotation.RiskTypes = classifierRiskTypes(verdicts.RiskTypes)
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
		RiskTypeError:    annotation.RiskTypeError,
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
	if annotation.RiskTypes != nil {
		_, _, _ = r.store.SaveRiskTypeAnnotation(ctx, riskclassifier.RiskTypeRecord{
			ActionID:    actionID,
			SessionID:   event.SessionID,
			ToolUseID:   event.ToolUseID,
			CommandHash: annotation.CommandHash,
			InputKind:   riskclassifier.RiskTypeInputRawCommand,
			Verdict:     riskTypeVerdict(annotation.RiskTypes),
		})
	}
}

func classifierRiskTypes(verdict *riskclassifier.RiskTypeVerdict) *risk.ClassifierRiskTypes {
	scores := make([]risk.ClassifierRiskTypeScore, len(verdict.Scores))
	for index, score := range verdict.Scores {
		scores[index] = risk.ClassifierRiskTypeScore{RiskType: score.RiskType, Score: score.Score}
	}
	return &risk.ClassifierRiskTypes{
		SchemaVersion:   verdict.SchemaVersion,
		Status:          verdict.Status,
		RiskTypes:       append([]string{}, verdict.RiskTypes...),
		PrimaryRiskType: verdict.PrimaryRiskType,
		Scores:          scores,
		Threshold:       verdict.Threshold,
		Abstained:       verdict.Abstained,
		Provenance: risk.ClassifierRiskTypeProvenance{
			ModelVersion:            verdict.Provenance.ModelVersion,
			SourceArtifactSHA256:    verdict.Provenance.SourceArtifactSHA256,
			SourceRevision:          verdict.Provenance.SourceRevision,
			SourcePR:                verdict.Provenance.SourcePR,
			AnnotationSHA256:        verdict.Provenance.AnnotationSHA256,
			AnnotationSchemaVersion: verdict.Provenance.AnnotationSchemaVersion,
			AnnotationPromptVersion: verdict.Provenance.AnnotationPromptVersion,
		},
	}
}

func riskTypeVerdict(annotation *risk.ClassifierRiskTypes) riskclassifier.RiskTypeVerdict {
	scores := make([]riskclassifier.RiskTypeScore, len(annotation.Scores))
	for index, score := range annotation.Scores {
		scores[index] = riskclassifier.RiskTypeScore{RiskType: score.RiskType, Score: score.Score}
	}
	return riskclassifier.RiskTypeVerdict{
		SchemaVersion:   annotation.SchemaVersion,
		Status:          annotation.Status,
		RiskTypes:       append([]string{}, annotation.RiskTypes...),
		PrimaryRiskType: annotation.PrimaryRiskType,
		Scores:          scores,
		Threshold:       annotation.Threshold,
		Abstained:       annotation.Abstained,
		Provenance: riskclassifier.RiskTypeProvenance{
			ModelVersion:            annotation.Provenance.ModelVersion,
			SourceArtifactSHA256:    annotation.Provenance.SourceArtifactSHA256,
			SourceRevision:          annotation.Provenance.SourceRevision,
			SourcePR:                annotation.Provenance.SourcePR,
			AnnotationSHA256:        annotation.Provenance.AnnotationSHA256,
			AnnotationSchemaVersion: annotation.Provenance.AnnotationSchemaVersion,
			AnnotationPromptVersion: annotation.Provenance.AnnotationPromptVersion,
		},
	}
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
