package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"time"
)

// LedgerLag reports export backlog without opening the store read-write:
// newest is the max updated_at cursor timestamp in authorization_actions
// (nil when the table is empty), pending counts rows past the given cursor.
// Read-only on purpose — doctor must never migrate a database out from
// under a running (possibly older) daemon.
func LedgerLag(ctx context.Context, dbPath string, cursor *LedgerCursor) (newest *time.Time, pending int, err error) {
	if _, err := os.Stat(dbPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	db, err := sql.Open("sqlite", readOnlyURI(dbPath))
	if err != nil {
		return nil, 0, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "pragma busy_timeout = 5000"); err != nil {
		return nil, 0, err
	}

	var rawNewest sql.NullString
	if err := db.QueryRowContext(ctx, "select max(updated_at_cursor_key) from authorization_actions").Scan(&rawNewest); err != nil {
		return nil, 0, err
	}
	if rawNewest.Valid && rawNewest.String != "" {
		parsed, err := parseLedgerTimestamp(rawNewest.String)
		if err != nil {
			return nil, 0, err
		}
		newest = &parsed
	}

	query := "select count(*) from authorization_actions"
	args := []any{}
	if cursor != nil {
		updatedAfter := ledgerTimestampCursorKeyFromTime(cursor.UpdatedAt)
		if cursor.ActionID != "" {
			query += " where updated_at_cursor_key > ? or (updated_at_cursor_key = ? and id > ?)"
			args = append(args, updatedAfter, updatedAfter, cursor.ActionID)
		} else {
			query += " where updated_at_cursor_key > ?"
			args = append(args, updatedAfter)
		}
	}
	if err := db.QueryRowContext(ctx, query, args...).Scan(&pending); err != nil {
		return nil, 0, err
	}
	return newest, pending, nil
}
