package sqlite

import (
	"context"
	"time"
)

func (s *Store) HistoricalTurnRecoveryBefore(ctx context.Context) (time.Time, error) {
	var value string
	if err := s.db.QueryRowContext(ctx, `select historical_before from turn_recovery_policy where id=1`).Scan(&value); err != nil {
		return time.Time{}, err
	}
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339Nano, value)
}

// An authenticated server acknowledgement supplies this bounded workspace
// request. Empty clears it. A changed request schedules one eligible rescan.
func (s *Store) SetHistoricalTurnRecoveryBefore(ctx context.Context, before time.Time) error {
	value := ""
	if !before.IsZero() {
		value = FormatTurnTime(before)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `update turn_recovery_policy set historical_before=? where id=1 and historical_before<>?`, value, value)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count > 0 {
		if _, err := tx.ExecContext(ctx, `update tool_usage_sources set turn_recovery_version=0`); err != nil {
			return err
		}
	}
	return tx.Commit()
}
