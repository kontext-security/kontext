package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"github.com/kontext-security/kontext/internal/modelusage"
	"time"
)

func recoveredTurnID(session string, started time.Time) string {
	return "turn_" + uuid.NewSHA1(uuid.NameSpaceOID, []byte("kontext:transcript-turn:v1\n"+session+"\n"+FormatTurnTime(started))).String()
}

// ResolveTurnID also covers hook actions queued before a late hook discovers
// its already-exported transcript fallback. Aliases survive daemon restarts.
func (s *Store) ResolveTurnID(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", nil
	}
	var canonical string
	err := s.db.QueryRowContext(ctx, `select turn_id from turn_aliases where alias_id=?`, id).Scan(&canonical)
	if errors.Is(err, sql.ErrNoRows) {
		return id, nil
	}
	return canonical, err
}

func (s *Store) SaveTurnCanonical(ctx context.Context, turn TurnRecord) (string, error) {
	if turn.ID == "" || turn.SessionID == "" || turn.StartedAt == "" {
		return "", errors.New("turn requires id, session and start time")
	}
	var text, sha256 any
	truncated := false
	if turn.Prompt.Mode == TurnPromptExcerpt {
		if turn.Prompt.Text == nil || turn.Prompt.SHA256 == nil || turn.Prompt.Truncated == nil {
			return "", errors.New("turn excerpt requires text, hash and truncation")
		}
		text, sha256, truncated = *turn.Prompt.Text, *turn.Prompt.SHA256, *turn.Prompt.Truncated
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	// Acquire the writer before reading, so a concurrent recovery cannot appear
	// between the canonical check and the hook insert (or force a read upgrade).
	if _, err := tx.ExecContext(ctx, `update turns set exported=exported where id=?`, turn.ID); err != nil {
		return "", err
	}
	var canonical string
	err = tx.QueryRowContext(ctx, `select turn_id from turn_aliases where alias_id=?`, turn.ID).Scan(&canonical)
	if err == nil {
		return canonical, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var existing string
	err = tx.QueryRowContext(ctx, `select id from turns where id=?`, turn.ID).Scan(&existing)
	if err == nil {
		return existing, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if started, parseErr := time.Parse(time.RFC3339Nano, turn.StartedAt); parseErr == nil {
		var boundary string
		err = tx.QueryRowContext(ctx, `select started_at from tool_usage_prompts where session_id=? and started_at>=? and started_at<=? order by started_at desc limit 1`, turn.SessionID, FormatTurnTime(started.Add(-modelusage.PromptHookSkew)), FormatTurnTime(started.Add(modelusage.PromptHookSkew))).Scan(&boundary)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		if err == nil {
			at, parseErr := time.Parse(time.RFC3339Nano, boundary)
			if parseErr != nil {
				return "", parseErr
			}
			id := recoveredTurnID(turn.SessionID, at)
			err = tx.QueryRowContext(ctx, `select id from turns where id=? and session_id=? and agent=?`, id, turn.SessionID, turn.Agent).Scan(&canonical)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return "", err
			}
			if err == nil {
				if _, err := tx.ExecContext(ctx, `insert into turn_aliases(alias_id,turn_id) values(?,?)`, turn.ID, canonical); err != nil {
					return "", err
				}
				return canonical, tx.Commit()
			}
		}
	}
	result, err := tx.ExecContext(ctx, `insert or ignore into turns(id, session_id, sequence, agent, started_at, source, prompt_mode, prompt_text, prompt_chars, prompt_sha256, prompt_truncated)
 select ?, ?, coalesce(max(sequence), 0) + 1, ?, ?, ?, ?, ?, ?, ?, ? from turns where session_id = ?`, turn.ID, turn.SessionID, turn.Agent, turn.StartedAt, turn.Source, turn.Prompt.Mode, text, turn.Prompt.Chars, sha256, truncated, turn.SessionID)
	if err != nil {
		return "", err
	}
	if count, err := result.RowsAffected(); err != nil {
		return "", err
	} else if count > 0 {
		if err := markToolUsageSourcesForRestamp(ctx, tx, turn.SessionID, nil); err != nil {
			return "", err
		}
	}
	return turn.ID, tx.Commit()
}
