package sqlite

import (
	"context"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/payloadcapture"
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

// MerlinAnnotations returns one append-only cursor page for managed upload.
// With ActionUpdatedThrough set, the page ends before the first annotation
// whose action is past that cursor (see annotationActionExported).
func (s *Store) MerlinAnnotations(ctx context.Context, opts MerlinAnnotationExportOptions) ([]MerlinAnnotationRecord, *MerlinAnnotationCursor, error) {
	query := strings.ReplaceAll(stepSafetyVerdictSelect, "from step_safety_verdicts", "from step_safety_verdicts annotation")
	args := []any{}
	conditions := []string{}
	if opts.CreatedAfter != nil {
		created := ledgerTimestampCursorKeyFromTime(*opts.CreatedAfter)
		if opts.CreatedAfterID != "" {
			// The row value lets SQLite seek idx_step_safety_created to the
			// cursor; the equivalent OR form walks it from the start.
			conditions = append(conditions, "(annotation.created_at, annotation.id) > (?, ?)")
			args = append(args, created, opts.CreatedAfterID)
		} else {
			conditions = append(conditions, "annotation.created_at > ?")
			args = append(args, created)
		}
	}
	if opts.ActionUpdatedThrough != nil {
		conditions = append(conditions, "exists (select 1 from authorization_actions action where action.id = annotation.action_id)")
	}
	exported, exportedArgs := annotationActionExported(opts.ActionUpdatedThrough, opts.ActionUpdatedThroughID)
	query = strings.Replace(query, "\nfrom ", ",\n  "+exported+"\nfrom ", 1)
	args = append(exportedArgs, args...)
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
	// A context kept on "Full tool calls and prompts" stays on the laptop once
	// the workspace moves off it, even if its annotation has not left yet.
	promptsAllowed := payloadcapture.PromptsAllowed(s.PayloadCaptureConfiguration())
	for rows.Next() {
		var actionExported bool
		record, err := scanStepSafetyVerdict(rows, &actionExported)
		if err != nil {
			return nil, nil, err
		}
		if !actionExported {
			break
		}
		record.UserFeedback = ""
		record.FeedbackAt = nil
		if !promptsAllowed {
			record.ReviewContext = nil
		}
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
