package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kontext-security/kontext-cli/internal/guard/riskclassifier"
)

// ErrClassifierVerdictNotFound reports feedback aimed at an action that has no
// classifier record.
var ErrClassifierVerdictNotFound = errors.New("classifier verdict not found")

// ClassifierVerdictRecord is a stored riskclassifier.Record plus its row
// identity and feedback timestamp.
type ClassifierVerdictRecord struct {
	ID string `json:"id"`
	riskclassifier.Record
	FeedbackAt *time.Time `json:"feedback_at,omitempty"`
}

const classifierVerdictsDDL = `
create table if not exists risk_classifier_verdicts (
  id text primary key,
  action_id text not null,
  session_id text not null,
  tool_use_id text,
  agent text,
  command_redacted text not null,
  command_hash text not null,
  command_truncated integer not null default 0,
  agent_task text,
  svm_verdict text,
  svm_score real,
  svm_threshold real,
  svm_model_version text,
  llm_verdict text,
  llm_raw text,
  llm_model text,
  llm_prompt_id text,
  llm_duration_ms integer,
  llm_cached integer not null default 0,
  llm_error text,
  risk_type_error text,
  enforced integer not null default 0,
  user_feedback text,
  feedback_at text,
  created_at text not null,
  -- One verdict per decided action. The feedback endpoint updates by
  -- action_id, so a second row for the same action would let one label land on
  -- two records and corrupt the ground truth silently.
  unique(action_id)
);

create index if not exists idx_risk_classifier_verdicts_session_created
on risk_classifier_verdicts(session_id, created_at);

create index if not exists idx_risk_classifier_verdicts_action
on risk_classifier_verdicts(action_id);
`

// classifierVerdictColumns is every column the current code reads and writes.
// "create table if not exists" is a no-op on a database that already has the
// table from an earlier build, so a column added after the table shipped would
// be missing while inserts and selects reference it unconditionally — verdicts
// would fail to insert and the verdict/feedback endpoints would 500. Each entry
// is applied with ensureColumn, so add to this list whenever the table gains a
// column.
var classifierVerdictColumns = []struct {
	name string
	def  string
}{
	{name: "tool_use_id", def: "text"},
	{name: "agent", def: "text"},
	{name: "command_truncated", def: "integer not null default 0"},
	{name: "agent_task", def: "text"},
	{name: "svm_verdict", def: "text"},
	{name: "svm_score", def: "real"},
	{name: "svm_threshold", def: "real"},
	{name: "svm_model_version", def: "text"},
	{name: "llm_verdict", def: "text"},
	{name: "llm_raw", def: "text"},
	{name: "llm_model", def: "text"},
	{name: "llm_prompt_id", def: "text"},
	{name: "llm_duration_ms", def: "integer"},
	{name: "llm_cached", def: "integer not null default 0"},
	{name: "llm_error", def: "text"},
	{name: "risk_type_error", def: "text"},
	{name: "enforced", def: "integer not null default 0"},
	{name: "user_feedback", def: "text"},
	{name: "feedback_at", def: "text"},
}

// ensureClassifierVerdictColumns brings an existing table up to the current
// schema.
func (s *Store) ensureClassifierVerdictColumns(ctx context.Context) error {
	for _, column := range classifierVerdictColumns {
		if err := s.ensureColumn(ctx, "risk_classifier_verdicts", column.name, column.def); err != nil {
			return err
		}
	}
	return nil
}

// SaveClassifierVerdict appends one observe-mode classifier record.
func (s *Store) SaveClassifierVerdict(ctx context.Context, record riskclassifier.Record) (ClassifierVerdictRecord, error) {
	if record.ActionID == "" || record.SessionID == "" {
		return ClassifierVerdictRecord{}, errors.New("classifier verdict requires action and session ids")
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	stored := ClassifierVerdictRecord{ID: "rcv_" + uuid.NewString(), Record: record}

	var svmVerdict, svmModelVersion any
	var svmScore, svmThreshold any
	if record.SVM != nil {
		svmVerdict = record.SVM.Verdict
		svmScore = record.SVM.Score
		svmThreshold = record.SVM.Threshold
		svmModelVersion = record.SVM.ModelVersion
	}
	var llmVerdict, llmRaw, llmModel, llmPromptID, llmDurationMs any
	llmCached := false
	if record.LLM != nil {
		llmVerdict = record.LLM.Verdict
		llmRaw = record.LLM.Raw
		llmModel = record.LLM.Model
		llmPromptID = nullIfEmpty(record.LLM.PromptID)
		llmDurationMs = record.LLM.DurationMs
		llmCached = record.LLM.Cached
	}
	_, err := s.db.ExecContext(ctx, `
insert into risk_classifier_verdicts(
  id, action_id, session_id, tool_use_id, agent,
  command_redacted, command_hash, command_truncated, agent_task,
  svm_verdict, svm_score, svm_threshold, svm_model_version,
  llm_verdict, llm_raw, llm_model, llm_prompt_id, llm_duration_ms, llm_cached, llm_error, risk_type_error,
  enforced, user_feedback, created_at
) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		stored.ID, record.ActionID, record.SessionID, nullIfEmpty(record.ToolUseID), nullIfEmpty(record.Agent),
		record.Command, record.CommandHash, record.CommandTruncated, nullIfEmpty(record.AgentTask),
		svmVerdict, svmScore, svmThreshold, svmModelVersion,
		llmVerdict, llmRaw, llmModel, llmPromptID, llmDurationMs, llmCached, nullIfEmpty(record.LLMError), nullIfEmpty(record.RiskTypeError),
		record.Enforced, nullIfEmpty(record.UserFeedback), record.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return ClassifierVerdictRecord{}, err
	}
	return stored, nil
}

// ClassifierVerdictsForSession returns a session's classifier records, newest
// first, matching the dashboard's event ordering.
func (s *Store) ClassifierVerdictsForSession(ctx context.Context, sessionID string) ([]ClassifierVerdictRecord, error) {
	rows, err := s.db.QueryContext(ctx, classifierVerdictSelect+`
where session_id = ?
order by created_at desc, id desc
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []ClassifierVerdictRecord{}
	for rows.Next() {
		record, err := scanClassifierVerdict(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

// ClassifierVerdictForAction returns the classifier record attached to a
// decided action.
func (s *Store) ClassifierVerdictForAction(ctx context.Context, actionID string) (ClassifierVerdictRecord, error) {
	row := s.db.QueryRowContext(ctx, classifierVerdictSelect+`
where action_id = ?
order by created_at desc, id desc
limit 1
	`, actionID)
	record, err := scanClassifierVerdict(row)
	if errors.Is(err, sql.ErrNoRows) {
		return ClassifierVerdictRecord{}, ErrClassifierVerdictNotFound
	}
	return record, err
}

// SetClassifierFeedback stamps the user's ground-truth label onto an action's
// classifier record. Labels are the two-sided feedback from the serving
// contract; anything else is rejected.
func (s *Store) SetClassifierFeedback(ctx context.Context, actionID, feedback string) (ClassifierVerdictRecord, error) {
	switch feedback {
	case riskclassifier.FeedbackShouldAllow, riskclassifier.FeedbackShouldBlock:
	default:
		return ClassifierVerdictRecord{}, fmt.Errorf("invalid classifier feedback %q", feedback)
	}
	result, err := s.db.ExecContext(ctx, `
update risk_classifier_verdicts
set user_feedback = ?, feedback_at = ?
where action_id = ?
	`, feedback, time.Now().UTC().Format(time.RFC3339Nano), actionID)
	if err != nil {
		return ClassifierVerdictRecord{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ClassifierVerdictRecord{}, err
	}
	if affected == 0 {
		return ClassifierVerdictRecord{}, ErrClassifierVerdictNotFound
	}
	return s.ClassifierVerdictForAction(ctx, actionID)
}

const classifierVerdictSelect = `
select id, action_id, session_id, coalesce(tool_use_id, ''), coalesce(agent, ''),
  command_redacted, command_hash, command_truncated, coalesce(agent_task, ''),
  svm_verdict, svm_score, svm_threshold, svm_model_version,
  llm_verdict, llm_raw, llm_model, coalesce(llm_prompt_id, ''), llm_duration_ms, llm_cached, coalesce(llm_error, ''), coalesce(risk_type_error, ''),
  enforced, coalesce(user_feedback, ''), feedback_at, created_at
from risk_classifier_verdicts
`

func scanClassifierVerdict(scanner interface{ Scan(...any) error }) (ClassifierVerdictRecord, error) {
	var record ClassifierVerdictRecord
	var svmVerdict, svmModelVersion sql.NullString
	var svmScore, svmThreshold sql.NullFloat64
	var llmVerdict, llmRaw, llmModel sql.NullString
	var llmPromptID string
	var llmDurationMs sql.NullInt64
	var llmCached bool
	var feedbackAt sql.NullString
	var created string
	if err := scanner.Scan(
		&record.ID, &record.ActionID, &record.SessionID, &record.ToolUseID, &record.Agent,
		&record.Command, &record.CommandHash, &record.CommandTruncated, &record.AgentTask,
		&svmVerdict, &svmScore, &svmThreshold, &svmModelVersion,
		&llmVerdict, &llmRaw, &llmModel, &llmPromptID, &llmDurationMs, &llmCached, &record.LLMError, &record.RiskTypeError,
		&record.Enforced, &record.UserFeedback, &feedbackAt, &created,
	); err != nil {
		return ClassifierVerdictRecord{}, err
	}
	if svmVerdict.Valid {
		record.SVM = &riskclassifier.SVMVerdict{
			Verdict:      svmVerdict.String,
			Score:        svmScore.Float64,
			Threshold:    svmThreshold.Float64,
			ModelVersion: svmModelVersion.String,
		}
	}
	if llmVerdict.Valid {
		record.LLM = &riskclassifier.LLMVerdict{
			Verdict:    llmVerdict.String,
			Raw:        llmRaw.String,
			Model:      llmModel.String,
			PromptID:   llmPromptID,
			DurationMs: llmDurationMs.Int64,
			Cached:     llmCached,
		}
	}
	if feedbackAt.Valid && feedbackAt.String != "" {
		parsed, err := parseStoredTime("classifier feedback_at", feedbackAt.String)
		if err != nil {
			return ClassifierVerdictRecord{}, err
		}
		record.FeedbackAt = &parsed
	}
	createdAt, err := parseStoredTime("classifier created_at", created)
	if err != nil {
		return ClassifierVerdictRecord{}, err
	}
	record.CreatedAt = createdAt
	return record, nil
}
