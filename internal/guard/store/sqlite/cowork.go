package sqlite

import (
	"context"
	"database/sql"
	"net/url"
	"time"
)

// HasCoworkSessionsSince reads the daemon's hook evidence without migrating or
// creating a store. Missing or unreadable stores leave sandbox status unknown.
func HasCoworkSessionsSince(ctx context.Context, dbPath string, since time.Time) (bool, error) {
	u := url.URL{Scheme: "file", Path: dbPath, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return false, err
	}
	defer db.Close()
	var observed bool
	err = db.QueryRowContext(ctx, `select exists (
		select 1 from agent_sessions
		where agent = 'claude_cowork' and julianday(updated_at) >= julianday(?)
	)`, since.UTC().Format(time.RFC3339Nano)).Scan(&observed)
	return observed, err
}
