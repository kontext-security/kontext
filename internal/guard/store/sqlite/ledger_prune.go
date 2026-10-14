package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
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
	// MaxRowBytes bounds the stored size of an action, its receipts and its
	// session. Callers set it far enough below the hosted body limit that
	// the action's minimum batch could never have been skipped as oversized.
	MaxRowBytes int
	Limit       int
}

// PruneExportedLedger deletes up to opts.Limit of the oldest actions, and
// their receipts, that the hosted ledger has accepted. An action counts as
// accepted only when it is behind the export cursor and its minimum batch
// could not have been skipped instead: it is not a recorded skip, it is
// small (MaxRowBytes), and its receipts are contiguous, so its batch never
// carried another action's receipts or hit the receipt limit. Clients before
// skips were recorded leave no other trace, so anything else is kept.
//
// It never deletes an action with an annotation still waiting for upload
// (the annotation export needs the action row), or the newest receipt, which
// the next receipt chains from. Candidates are found without the write lock,
// then re-checked and deleted in one IMMEDIATE transaction, so the lock is
// held for at most opts.Limit lookups and an annotation written meanwhile
// still keeps its action. Risk-type annotations insert only while their
// action exists; step-safety verdicts are written for actions being decided
// now, never for ones old enough to prune. Freed pages are reused; the file
// is not shrunk.
func (s *Store) PruneExportedLedger(ctx context.Context, opts LedgerPruneOptions) (int, error) {
	if opts.Limit <= 0 || opts.MaxRowBytes <= 0 || opts.ActionsExportedBefore.IsZero() || opts.OlderThan.IsZero() {
		return 0, nil
	}
	before := opts.ActionsExportedBefore
	if opts.OlderThan.Before(before) {
		before = opts.OlderThan
	}
	eligible := `select a.id from authorization_actions a
where a.updated_at_cursor_key < ?
  and not exists (select 1 from ledger_export_skips skip where skip.action_id = a.id)
  and (select count(*) = coalesce(max(r.rowid) - min(r.rowid) + 1, 0) from authorization_receipts r where r.action_id = a.id)
  and ` + storedBytes(authorizationActionsSelect, "a") + `
    + (select coalesce(sum(` + storedBytes(authorizationReceiptsSelect, "r") + `), 0) from authorization_receipts r where r.action_id = a.id)
    + (select coalesce(sum(` + storedBytes(agentSessionsSelect, "session") + `), 0) from agent_sessions session where session.id = a.session_id) <= ?`
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
		eligible += condition + ")"
	}
	// WAL readers never block writers, so walking past rows kept forever
	// costs the hook path nothing here.
	candidates, err := queryStrings(ctx, s.db, eligible+"\norder by a.updated_at_cursor_key, a.id\nlimit ?", append(slices.Clone(args), opts.Limit)...)
	if err != nil || len(candidates) == 0 {
		return 0, err
	}
	pruneCandidatesFound()

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	// IMMEDIATE takes the write lock before the re-check, so the eligibility
	// seen there still holds when the rows are deleted.
	if _, err := conn.ExecContext(ctx, "begin immediate"); err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "rollback")
		}
	}()
	deleted := 0
	for _, chunk := range stringChunks(candidates) {
		placeholders := strings.TrimRight(strings.Repeat("?,", len(chunk)), ",")
		chunkArgs := make([]any, 0, len(chunk))
		for _, id := range chunk {
			chunkArgs = append(chunkArgs, id)
		}
		ids, err := queryStrings(ctx, conn, eligible+fmt.Sprintf("\n  and a.id in (%s)", placeholders), append(slices.Clone(args), chunkArgs...)...)
		if err != nil {
			return 0, err
		}
		if len(ids) == 0 {
			continue
		}
		placeholders = strings.TrimRight(strings.Repeat("?,", len(ids)), ",")
		idArgs := make([]any, 0, len(ids))
		for _, id := range ids {
			idArgs = append(idArgs, id)
		}
		if _, err := conn.ExecContext(ctx, fmt.Sprintf(`delete from authorization_receipts where action_id in (%s)
  and rowid < (select max(rowid) from authorization_receipts)`, placeholders), idArgs...); err != nil {
			return 0, err
		}
		if _, err := conn.ExecContext(ctx, fmt.Sprintf(`delete from authorization_actions where id in (%s)`, placeholders), idArgs...); err != nil {
			return 0, err
		}
		deleted += len(ids)
	}
	if _, err := conn.ExecContext(ctx, "commit"); err != nil {
		return 0, err
	}
	committed = true
	return deleted, nil
}

// pruneCandidatesFound lets tests write between finding candidates and
// re-checking them under the write lock.
var pruneCandidatesFound = func() {}

// storedBytes sums the stored length of every column an export select reads,
// so the size guard cannot drift from what an upload carries.
func storedBytes(selectSQL, alias string) string {
	columns := selectSQL[strings.Index(selectSQL, "select")+len("select") : strings.Index(selectSQL, "\nfrom ")]
	var terms []string
	for _, column := range strings.Split(columns, ",") {
		terms = append(terms, fmt.Sprintf("coalesce(length(%s.%s), 0)", alias, strings.TrimSpace(column)))
	}
	return strings.Join(terms, " + ")
}

type querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func queryStrings(ctx context.Context, db querier, query string, args ...any) ([]string, error) {
	rows, err := db.QueryContext(ctx, query, args...)
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
