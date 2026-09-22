package sqlite

import (
	"context"
	"database/sql"
	"net/url"
)

// HasCoworkSession reads the daemon's hook evidence without migrating or
// creating a store. Missing or unreadable stores leave sandbox status unknown.
func HasCoworkSession(ctx context.Context, dbPath, id string) (bool, error) {
	u := url.URL{Scheme: "file", Path: dbPath, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return false, err
	}
	defer db.Close()
	var observed bool
	err = db.QueryRowContext(ctx, `select exists (
		select 1 from agent_sessions
		where id = ? and agent = 'claude_cowork'
	)`, id).Scan(&observed)
	return observed, err
}
