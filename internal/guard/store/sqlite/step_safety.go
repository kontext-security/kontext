package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
	"github.com/kontext-security/kontext/internal/guard/stepsafety"
)

var ErrStepSafetyVerdictNotFound = errors.New("step-safety verdict not found")

type StepSafetyRecord struct {
	ID                 string     `json:"id"`
	ActionID           string     `json:"action_id"`
	SessionID          string     `json:"session_id"`
	ToolUseID          string     `json:"tool_use_id,omitempty"`
	ToolName           string     `json:"tool_name"`
	UnsafeProbability  *float64   `json:"unsafe_probability,omitempty"`
	ShadowDecision     string     `json:"shadow_decision"`
	Threshold          float64    `json:"threshold"`
	ModelVersion       string     `json:"model_version"`
	LatencyMS          float64    `json:"latency_ms"`
	ErrorCode          string     `json:"error_code,omitempty"`
	Enforced           bool       `json:"enforced"`
	UserRequestPresent bool       `json:"user_request_present"`
	HistoryPresent     bool       `json:"history_present"`
	ToolSchemasPresent bool       `json:"tool_schemas_present"`
	UserFeedback       string     `json:"user_feedback,omitempty"`
	FeedbackAt         *time.Time `json:"feedback_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}

const stepSafetyVerdictsDDL = `
create table if not exists step_safety_verdicts (
  id text primary key,
  action_id text not null,
  session_id text not null,
  tool_use_id text,
  tool_name text not null,
  unsafe_probability real,
  shadow_decision text not null,
  threshold real not null,
  model_version text not null,
  latency_ms real not null,
  error_code text,
  enforced integer not null default 0,
  user_request_present integer not null default 0,
  history_present integer not null default 0,
  tool_schemas_present integer not null default 0,
  user_feedback text,
  feedback_at text,
  created_at text not null,
  unique(action_id)
);

create index if not exists idx_step_safety_session_created
on step_safety_verdicts(session_id, created_at);

create index if not exists idx_step_safety_action
on step_safety_verdicts(action_id);
`

func (s *Store) ensureStepSafetyVerdictColumns(ctx context.Context) error {
	for _, column := range []struct{ name, def string }{
		{name: "user_request_present", def: "integer not null default 0"},
		{name: "history_present", def: "integer not null default 0"},
		{name: "tool_schemas_present", def: "integer not null default 0"},
	} {
		if err := s.ensureColumn(ctx, "step_safety_verdicts", column.name, column.def); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) SaveStepSafetyVerdict(ctx context.Context, record StepSafetyRecord) (StepSafetyRecord, error) {
	if record.ActionID == "" || record.SessionID == "" {
		return StepSafetyRecord{}, errors.New("step-safety verdict requires action and session ids")
	}
	if record.ModelVersion == "" {
		return StepSafetyRecord{}, errors.New("step-safety verdict requires a model version")
	}
	if record.ShadowDecision != stepsafety.DecisionSafe &&
		record.ShadowDecision != stepsafety.DecisionUnsafe &&
		record.ShadowDecision != stepsafety.DecisionUnavailable {
		return StepSafetyRecord{}, fmt.Errorf("invalid step-safety shadow decision %q", record.ShadowDecision)
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	}
	if record.ID == "" {
		record.ID = "ssv_" + uuid.NewString()
	}
	_, err := s.db.ExecContext(ctx, `
insert into step_safety_verdicts(
  id, action_id, session_id, tool_use_id, tool_name,
  unsafe_probability, shadow_decision, threshold, model_version,
  latency_ms, error_code, enforced,
  user_request_present, history_present, tool_schemas_present,
  user_feedback, feedback_at, created_at
) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		record.ID, record.ActionID, record.SessionID, nullIfEmpty(record.ToolUseID), record.ToolName,
		record.UnsafeProbability, record.ShadowDecision, record.Threshold, record.ModelVersion,
		record.LatencyMS, nullIfEmpty(record.ErrorCode), record.Enforced,
		record.UserRequestPresent, record.HistoryPresent, record.ToolSchemasPresent,
		nullIfEmpty(record.UserFeedback), storedOptionalTime(record.FeedbackAt), record.CreatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return StepSafetyRecord{}, err
	}
	return record, nil
}

func (s *Store) StepSafetyVerdictsForSession(ctx context.Context, sessionID string) ([]StepSafetyRecord, error) {
	rows, err := s.db.QueryContext(ctx, stepSafetyVerdictSelect+`
where session_id = ?
order by created_at desc, id desc
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []StepSafetyRecord{}
	for rows.Next() {
		record, err := scanStepSafetyVerdict(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *Store) StepSafetyVerdictForAction(ctx context.Context, actionID string) (StepSafetyRecord, error) {
	row := s.db.QueryRowContext(ctx, stepSafetyVerdictSelect+`
where action_id = ?
limit 1
	`, actionID)
	record, err := scanStepSafetyVerdict(row)
	if errors.Is(err, sql.ErrNoRows) {
		return StepSafetyRecord{}, ErrStepSafetyVerdictNotFound
	}
	return record, err
}

func (s *Store) SetStepSafetyFeedback(ctx context.Context, actionID, feedback string) (StepSafetyRecord, error) {
	switch feedback {
	case riskclassifier.FeedbackShouldAllow, riskclassifier.FeedbackShouldBlock:
	default:
		return StepSafetyRecord{}, fmt.Errorf("invalid step-safety feedback %q", feedback)
	}
	result, err := s.db.ExecContext(ctx, `
update step_safety_verdicts
set user_feedback = ?, feedback_at = ?
where action_id = ?
	`, feedback, time.Now().UTC().Format(time.RFC3339Nano), actionID)
	if err != nil {
		return StepSafetyRecord{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return StepSafetyRecord{}, err
	}
	if affected == 0 {
		return StepSafetyRecord{}, ErrStepSafetyVerdictNotFound
	}
	return s.StepSafetyVerdictForAction(ctx, actionID)
}

const stepSafetyVerdictSelect = `
select id, action_id, session_id, coalesce(tool_use_id, ''), tool_name,
  unsafe_probability, shadow_decision, threshold, model_version,
  latency_ms, coalesce(error_code, ''), enforced,
  user_request_present, history_present, tool_schemas_present,
  coalesce(user_feedback, ''),
  feedback_at, created_at
from step_safety_verdicts
`

func scanStepSafetyVerdict(scanner interface{ Scan(...any) error }) (StepSafetyRecord, error) {
	var record StepSafetyRecord
	var probability sql.NullFloat64
	var feedbackAt sql.NullString
	var createdAt string
	if err := scanner.Scan(
		&record.ID, &record.ActionID, &record.SessionID, &record.ToolUseID, &record.ToolName,
		&probability, &record.ShadowDecision, &record.Threshold, &record.ModelVersion,
		&record.LatencyMS, &record.ErrorCode, &record.Enforced,
		&record.UserRequestPresent, &record.HistoryPresent, &record.ToolSchemasPresent,
		&record.UserFeedback,
		&feedbackAt, &createdAt,
	); err != nil {
		return StepSafetyRecord{}, err
	}
	if probability.Valid {
		record.UnsafeProbability = &probability.Float64
	}
	if feedbackAt.Valid && feedbackAt.String != "" {
		parsed, err := parseStoredTime("step-safety feedback_at", feedbackAt.String)
		if err != nil {
			return StepSafetyRecord{}, err
		}
		record.FeedbackAt = &parsed
	}
	parsed, err := parseStoredTime("step-safety created_at", createdAt)
	if err != nil {
		return StepSafetyRecord{}, err
	}
	record.CreatedAt = parsed
	return record, nil
}

func storedOptionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC().Format(time.RFC3339Nano)
}
