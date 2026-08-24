package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
)

// RiskTypeAnnotationRecord is the append-only local and wire record. The ID is
// deterministic across retries, and the unique (action, model) key makes the
// retrospective command idempotent without updating historical facts.
type RiskTypeAnnotationRecord struct {
	ID string `json:"id"`
	riskclassifier.RiskTypeRecord
}

type RiskTypeAnnotationExportOptions struct {
	CreatedAfter           *time.Time
	CreatedAfterID         string
	ActionUpdatedThrough   *time.Time
	ActionUpdatedThroughID string
	Limit                  int
}

type RiskTypeAnnotationCursor struct {
	CreatedAt    time.Time
	AnnotationID string
}

type RiskTypeEnrichmentItem struct {
	ActionID       string                         `json:"action_id"`
	ToolUseID      string                         `json:"tool_use_id,omitempty"`
	ToolName       string                         `json:"tool_name"`
	Command        string                         `json:"command"`
	AlreadyPresent bool                           `json:"already_present"`
	Annotation     riskclassifier.RiskTypeVerdict `json:"annotation"`
}

type RiskTypeEnrichmentResult struct {
	EligibleRisky   int                      `json:"eligible_risky"`
	Inserted        int                      `json:"inserted"`
	AlreadyPresent  int                      `json:"already_present"`
	IneligibleRisky int                      `json:"ineligible_risky"`
	Items           []RiskTypeEnrichmentItem `json:"items"`
}

const riskTypeAnnotationsDDL = `
create table if not exists risk_type_annotations (
  id text primary key,
  action_id text not null,
  session_id text not null,
  tool_use_id text,
  command_hash text not null,
  input_kind text not null,
  schema_version text not null,
  model_version text not null,
  annotation_json text not null,
  created_at text not null,
  unique(action_id, model_version)
);

create index if not exists idx_risk_type_annotations_created
on risk_type_annotations(created_at, id);

create index if not exists idx_risk_type_annotations_action
on risk_type_annotations(action_id);
`

func (s *Store) ensureRiskTypeAnnotations(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, riskTypeAnnotationsDDL)
	return err
}

// SaveRiskTypeAnnotation appends a result or returns the byte-equivalent
// existing result for the same action and model. It never updates a row.
func (s *Store) SaveRiskTypeAnnotation(ctx context.Context, record riskclassifier.RiskTypeRecord) (RiskTypeAnnotationRecord, bool, error) {
	if record.ActionID == "" || record.SessionID == "" || record.CommandHash == "" {
		return RiskTypeAnnotationRecord{}, false, errors.New("risk-type annotation requires action, session, and command hash")
	}
	switch record.InputKind {
	case riskclassifier.RiskTypeInputRawCommand, riskclassifier.RiskTypeInputStoredRedactedCommand:
	default:
		return RiskTypeAnnotationRecord{}, false, fmt.Errorf("unknown risk-type input kind %q", record.InputKind)
	}
	if err := record.Verdict.Validate(); err != nil {
		return RiskTypeAnnotationRecord{}, false, err
	}
	if err := s.validateRiskTypeAnnotationAction(ctx, record); err != nil {
		return RiskTypeAnnotationRecord{}, false, err
	}
	if record.CreatedAt.IsZero() {
		record.CreatedAt = time.Now().UTC()
	} else {
		record.CreatedAt = record.CreatedAt.UTC()
	}
	annotationJSON, err := json.Marshal(record.Verdict)
	if err != nil {
		return RiskTypeAnnotationRecord{}, false, fmt.Errorf("marshal risk-type annotation: %w", err)
	}
	id := riskTypeAnnotationID(record.ActionID, record.Verdict.Provenance.ModelVersion)
	result, err := s.db.ExecContext(ctx, `
insert into risk_type_annotations(
  id, action_id, session_id, tool_use_id, command_hash, input_kind,
  schema_version, model_version, annotation_json, created_at
) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
on conflict(action_id, model_version) do nothing
	`, id, record.ActionID, record.SessionID, nullIfEmpty(record.ToolUseID), record.CommandHash, record.InputKind,
		record.Verdict.SchemaVersion, record.Verdict.Provenance.ModelVersion, string(annotationJSON), record.CreatedAt.Format(time.RFC3339Nano))
	if err != nil {
		return RiskTypeAnnotationRecord{}, false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return RiskTypeAnnotationRecord{}, false, err
	}
	stored, err := s.RiskTypeAnnotationForActionModel(ctx, record.ActionID, record.Verdict.Provenance.ModelVersion)
	if err != nil {
		return RiskTypeAnnotationRecord{}, false, err
	}
	if affected == 0 && !equivalentRiskTypeRecord(stored.RiskTypeRecord, record) {
		return RiskTypeAnnotationRecord{}, false, fmt.Errorf("risk-type annotation for action %s and model %s already exists with different content", record.ActionID, record.Verdict.Provenance.ModelVersion)
	}
	return stored, affected == 1, nil
}

func (s *Store) validateRiskTypeAnnotationAction(ctx context.Context, record riskclassifier.RiskTypeRecord) error {
	var sessionID string
	var toolUseID sql.NullString
	err := s.db.QueryRowContext(ctx, `
select session_id, tool_use_id
from authorization_actions
where id = ?
	`, record.ActionID).Scan(&sessionID, &toolUseID)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("risk-type annotation references unknown action %s", record.ActionID)
	}
	if err != nil {
		return err
	}
	if sessionID != record.SessionID {
		return fmt.Errorf("risk-type annotation session %s does not match action %s", record.SessionID, record.ActionID)
	}
	if storedToolUseID := toolUseID.String; record.ToolUseID != "" && storedToolUseID != record.ToolUseID {
		return fmt.Errorf("risk-type annotation tool use %q does not match action %s", record.ToolUseID, record.ActionID)
	}
	return nil
}

func riskTypeAnnotationID(actionID, modelVersion string) string {
	digest := sha256.Sum256([]byte(actionID + "\x00" + modelVersion))
	return "rta_" + hex.EncodeToString(digest[:])
}

func equivalentRiskTypeRecord(stored, incoming riskclassifier.RiskTypeRecord) bool {
	// CreatedAt belongs to the first successful append and is intentionally not
	// compared on an idempotent replay.
	stored.CreatedAt = time.Time{}
	incoming.CreatedAt = time.Time{}
	left, leftErr := json.Marshal(stored)
	right, rightErr := json.Marshal(incoming)
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}

func (s *Store) RiskTypeAnnotationForActionModel(ctx context.Context, actionID, modelVersion string) (RiskTypeAnnotationRecord, error) {
	row := s.db.QueryRowContext(ctx, riskTypeAnnotationSelect+`
where annotation.action_id = ? and annotation.model_version = ?
limit 1
	`, actionID, modelVersion)
	return scanRiskTypeAnnotation(row)
}

// RiskTypeAnnotations returns one append-only cursor page for managed upload.
func (s *Store) RiskTypeAnnotations(ctx context.Context, opts RiskTypeAnnotationExportOptions) ([]RiskTypeAnnotationRecord, *RiskTypeAnnotationCursor, error) {
	query := riskTypeAnnotationSelect
	args := []any{}
	conditions := []string{}
	if opts.CreatedAfter != nil {
		created := opts.CreatedAfter.UTC().Format(time.RFC3339Nano)
		if opts.CreatedAfterID != "" {
			conditions = append(conditions, "(annotation.created_at > ? or (annotation.created_at = ? and annotation.id > ?))")
			args = append(args, created, created, opts.CreatedAfterID)
		} else {
			conditions = append(conditions, "annotation.created_at > ?")
			args = append(args, created)
		}
	}
	if opts.ActionUpdatedThrough != nil {
		updated := ledgerTimestampCursorKeyFromTime(*opts.ActionUpdatedThrough)
		if opts.ActionUpdatedThroughID != "" {
			conditions = append(conditions, `exists (
  select 1 from authorization_actions action
  where action.id = annotation.action_id
    and (action.updated_at_cursor_key < ? or (action.updated_at_cursor_key = ? and action.id <= ?))
)`)
			args = append(args, updated, updated, opts.ActionUpdatedThroughID)
		} else {
			conditions = append(conditions, `exists (
  select 1 from authorization_actions action
  where action.id = annotation.action_id
    and action.updated_at_cursor_key < ?
)`)
			args = append(args, updated)
		}
	}
	if len(conditions) > 0 {
		query += "\nwhere " + strings.Join(conditions, "\nand ")
	}
	query += "\norder by annotation.created_at, annotation.id"
	if opts.Limit > 0 {
		query += "\nlimit ?"
		args = append(args, opts.Limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	records := []RiskTypeAnnotationRecord{}
	for rows.Next() {
		record, err := scanRiskTypeAnnotation(rows)
		if err != nil {
			return nil, nil, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(records) == 0 {
		return records, nil, nil
	}
	last := records[len(records)-1]
	return records, &RiskTypeAnnotationCursor{CreatedAt: last.CreatedAt, AnnotationID: last.ID}, nil
}

const riskTypeAnnotationSelect = `
select annotation.id, annotation.action_id, annotation.session_id,
  coalesce(annotation.tool_use_id, ''), annotation.command_hash,
  annotation.input_kind, annotation.schema_version, annotation.model_version,
  annotation.annotation_json, annotation.created_at
from risk_type_annotations annotation`

func scanRiskTypeAnnotation(scanner interface{ Scan(...any) error }) (RiskTypeAnnotationRecord, error) {
	var record RiskTypeAnnotationRecord
	var schemaVersion, modelVersion, annotationJSON, created string
	if err := scanner.Scan(&record.ID, &record.ActionID, &record.SessionID, &record.ToolUseID, &record.CommandHash,
		&record.InputKind, &schemaVersion, &modelVersion, &annotationJSON, &created); err != nil {
		return RiskTypeAnnotationRecord{}, err
	}
	if err := json.Unmarshal([]byte(annotationJSON), &record.Verdict); err != nil {
		return RiskTypeAnnotationRecord{}, fmt.Errorf("decode stored risk-type annotation: %w", err)
	}
	if record.Verdict.SchemaVersion != schemaVersion || record.Verdict.Provenance.ModelVersion != modelVersion {
		return RiskTypeAnnotationRecord{}, errors.New("stored risk-type annotation mirrors disagree")
	}
	createdAt, err := parseStoredTime("risk type created_at", created)
	if err != nil {
		return RiskTypeAnnotationRecord{}, err
	}
	record.CreatedAt = createdAt
	return record, nil
}

// EnrichRiskyShellCalls classifies every locally recorded binary-risky shell
// call with no annotation for this model. Commands are the stored redacted
// evidence because raw historical payloads are intentionally unavailable.
func (s *Store) EnrichRiskyShellCalls(ctx context.Context, model *riskclassifier.RiskTypeSVM) (RiskTypeEnrichmentResult, error) {
	if model == nil {
		return RiskTypeEnrichmentResult{}, errors.New("risk-type model is required")
	}
	rows, err := s.db.QueryContext(ctx, `
select r.action_id, r.session_id, coalesce(r.tool_use_id, ''),
  coalesce(a.tool_name, ''), r.command_redacted, r.command_hash
from risk_classifier_verdicts r
left join authorization_actions a on a.id = r.action_id
where r.svm_verdict = ?
order by r.created_at, r.id
	`, riskclassifier.VerdictRisky)
	if err != nil {
		return RiskTypeEnrichmentResult{}, err
	}
	type candidate struct {
		actionID, sessionID, toolUseID, toolName, command, commandHash string
	}
	candidates := []candidate{}
	result := RiskTypeEnrichmentResult{Items: []RiskTypeEnrichmentItem{}}
	for rows.Next() {
		var row candidate
		if err := rows.Scan(&row.actionID, &row.sessionID, &row.toolUseID, &row.toolName, &row.command, &row.commandHash); err != nil {
			rows.Close()
			return RiskTypeEnrichmentResult{}, err
		}
		if !riskclassifier.IsShellCommandTool(row.toolName) {
			result.IneligibleRisky++
			continue
		}
		candidates = append(candidates, row)
	}
	if err := rows.Close(); err != nil {
		return RiskTypeEnrichmentResult{}, err
	}

	modelVersion := model.Classify("").Provenance.ModelVersion
	for _, candidate := range candidates {
		if existing, err := s.RiskTypeAnnotationForActionModel(ctx, candidate.actionID, modelVersion); err == nil {
			result.EligibleRisky++
			result.AlreadyPresent++
			result.Items = append(result.Items, RiskTypeEnrichmentItem{
				ActionID:       candidate.actionID,
				ToolUseID:      candidate.toolUseID,
				ToolName:       candidate.toolName,
				Command:        candidate.command,
				AlreadyPresent: true,
				Annotation:     existing.Verdict,
			})
			continue
		} else if !errors.Is(err, sql.ErrNoRows) {
			return RiskTypeEnrichmentResult{}, err
		}
		verdict := model.Classify(candidate.command)
		stored, inserted, err := s.SaveRiskTypeAnnotation(ctx, riskclassifier.RiskTypeRecord{
			ActionID:    candidate.actionID,
			SessionID:   candidate.sessionID,
			ToolUseID:   candidate.toolUseID,
			CommandHash: candidate.commandHash,
			InputKind:   riskclassifier.RiskTypeInputStoredRedactedCommand,
			Verdict:     verdict,
		})
		if err != nil {
			return RiskTypeEnrichmentResult{}, err
		}
		result.EligibleRisky++
		if inserted {
			result.Inserted++
		} else {
			result.AlreadyPresent++
		}
		result.Items = append(result.Items, RiskTypeEnrichmentItem{
			ActionID:       candidate.actionID,
			ToolUseID:      candidate.toolUseID,
			ToolName:       candidate.toolName,
			Command:        candidate.command,
			AlreadyPresent: !inserted,
			Annotation:     stored.Verdict,
		})
	}
	return result, nil
}
