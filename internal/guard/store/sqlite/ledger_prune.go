package sqlite

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// ledgerExportSkipsDDL records actions the managed stream advanced past
// without the hosted ledger accepting them (a minimum batch over the hosted
// limits). Retention never deletes those rows: they are the only copy.
const ledgerExportSkipsDDL = `
create table if not exists ledger_export_skips (
 action_id text primary key,
 reason text not null,
 created_at text not null
);
`

// RecordLedgerExportSkips marks actions the stream is about to advance past
// without a hosted acceptance.
func (s *Store) RecordLedgerExportSkips(ctx context.Context, actionIDs []string, reason string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, id := range uniqueStrings(actionIDs) {
		if _, err := s.db.ExecContext(ctx, `insert or ignore into ledger_export_skips(action_id, reason, created_at) values(?,?,?)`, id, reason, now); err != nil {
			return err
		}
	}
	return nil
}

// LedgerPruneOptions describes what the hosted ledger has accepted. The
// cursors are the managed stream's persisted export positions; nil means
// nothing of that kind has been exported yet.
type LedgerPruneOptions struct {
	// ActionsExportedBefore is the persisted action cursor. Only actions
	// strictly before it are eligible.
	ActionsExportedBefore time.Time
	RiskTypeCreatedAfter  *time.Time
	RiskTypeAnnotationID  string
	MerlinCreatedAfter    *time.Time
	MerlinAnnotationID    string
	// OlderThan keeps recent history local regardless of export state.
	OlderThan time.Time
	// MaxRowBytes keeps any action whose stored payload is large enough that
	// an older client may have skipped it as an oversized minimum batch
	// before skips were recorded.
	MaxRowBytes int
	Limit       int
}

// PruneExportedLedger deletes up to opts.Limit of the oldest actions, and
// their receipts, that the hosted ledger has accepted. It never deletes an
// action with an annotation still waiting for upload (the annotation export
// needs the action row), a recorded skip, or the newest receipt, which the
// next receipt chains from. Freed pages are reused; the file is not shrunk.
func (s *Store) PruneExportedLedger(ctx context.Context, opts LedgerPruneOptions) (int, error) {
	if opts.Limit <= 0 || opts.MaxRowBytes <= 0 || opts.ActionsExportedBefore.IsZero() || opts.OlderThan.IsZero() {
		return 0, nil
	}
	before := opts.ActionsExportedBefore
	if opts.OlderThan.Before(before) {
		before = opts.OlderThan
	}
	query := `select a.id from authorization_actions a
where a.updated_at_cursor_key < ?
  and not exists (select 1 from ledger_export_skips skip where skip.action_id = a.id)
  and coalesce(length(a.tool_input_captured_json), 0) + coalesce(length(a.tool_output_captured_json), 0)
    + coalesce(length(a.decision_fact_json), 0) + coalesce(length(a.context_json), 0)
    + coalesce(length(a.risk_event_json), 0) + coalesce(length(a.parameters_redacted_json), 0)
    + coalesce(length(a.identity_context_json), 0)
    + (select coalesce(sum(length(r.receipt_payload_json)), 0) from authorization_receipts r where r.action_id = a.id) <= ?`
	args := []any{ledgerTimestampCursorKeyFromTime(before), opts.MaxRowBytes}
	// Mirror the export queries: an annotation they would still return has
	// not been uploaded yet.
	for _, pending := range []struct {
		table     string
		createdAt *time.Time
		id        string
	}{
		{"risk_type_annotations", opts.RiskTypeCreatedAfter, opts.RiskTypeAnnotationID},
		{"step_safety_verdicts", opts.MerlinCreatedAfter, opts.MerlinAnnotationID},
	} {
		condition := fmt.Sprintf("\n  and not exists (select 1 from %s annotation where annotation.action_id = a.id", pending.table)
		switch {
		case pending.createdAt == nil:
		case pending.id != "":
			created := pending.createdAt.UTC().Format(time.RFC3339Nano)
			condition += " and (annotation.created_at > ? or (annotation.created_at = ? and annotation.id > ?))"
			args = append(args, created, created, pending.id)
		default:
			condition += " and annotation.created_at > ?"
			args = append(args, pending.createdAt.UTC().Format(time.RFC3339Nano))
		}
		query += condition + ")"
	}
	query += "\norder by a.updated_at_cursor_key, a.id\nlimit ?"
	args = append(args, opts.Limit)
	ids, err := s.queryStrings(ctx, query, args...)
	if err != nil || len(ids) == 0 {
		return 0, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	for _, chunk := range stringChunks(ids) {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(chunk)), ",")
		args := make([]any, 0, len(chunk))
		for _, id := range chunk {
			args = append(args, id)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`delete from authorization_receipts where action_id in (%s)
  and rowid < (select max(rowid) from authorization_receipts)`, placeholders), args...); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf(`delete from authorization_actions where id in (%s)`, placeholders), args...); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(ids), nil
}

func (s *Store) queryStrings(ctx context.Context, query string, args ...any) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}
