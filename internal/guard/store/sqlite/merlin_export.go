package sqlite

import (
	"context"
	"strings"
	"time"
)

// Feedback is mutable and deliberately omitted from the append-only wire record.
type MerlinAnnotationRecord struct {
	SchemaVersion string `json:"schema_version"`
	StepSafetyRecord
}
type MerlinAnnotationExportOptions struct {
	CreatedAfter           *time.Time
	CreatedAfterID         string
	ActionUpdatedThrough   *time.Time
	ActionUpdatedThroughID string
	Limit                  int
}
type MerlinAnnotationCursor struct {
	CreatedAt    time.Time
	AnnotationID string
}

func (s *Store) MerlinAnnotations(ctx context.Context, opts MerlinAnnotationExportOptions) ([]MerlinAnnotationRecord, *MerlinAnnotationCursor, error) {
	query := strings.ReplaceAll(stepSafetyVerdictSelect, "from step_safety_verdicts", "from step_safety_verdicts annotation")
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
	records := []MerlinAnnotationRecord{}
	for rows.Next() {
		record, err := scanStepSafetyVerdict(rows)
		if err != nil {
			return nil, nil, err
		}
		record.UserFeedback = ""
		record.FeedbackAt = nil
		records = append(records, MerlinAnnotationRecord{SchemaVersion: "merlin_annotation/v1", StepSafetyRecord: record})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if len(records) == 0 {
		return records, nil, nil
	}
	last := records[len(records)-1]
	return records, &MerlinAnnotationCursor{CreatedAt: last.CreatedAt, AnnotationID: last.ID}, nil
}
