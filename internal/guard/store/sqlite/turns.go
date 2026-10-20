package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/modelusage"
)

// turnsDDL holds the turns the daemon minted on prompt hooks and the turn
// boundaries the usage reader found in transcripts. A turn never changes
// after it is minted, so its outbox is an exported flag acknowledged by turn
// id. Both tables live here rather than in memory because the usage reader
// runs later, in the stream worker, and after a restart.
const turnsDDL = `
create table if not exists turns (
 id text primary key,
 session_id text not null,
 sequence integer not null,
 agent text not null,
 started_at text not null,
 source text not null,
 prompt_mode text not null,
 prompt_text text,
 prompt_chars integer not null,
 prompt_sha256 text,
 prompt_truncated integer not null default 0,
 exported integer not null default 0,
 unique(session_id, sequence)
);
create index if not exists turns_session_started on turns(session_id, started_at);
create index if not exists turns_pending on turns(exported, started_at);
-- Turn boundaries per session, from every transcript of the session. A
-- subagent transcript has none of its own and is matched against these.
create table if not exists tool_usage_prompts (
 session_id text not null,
 started_at text not null,
 primary key(session_id, started_at)
);
`

// TurnSchemaVersion is the wire schema of a turn record.
const TurnSchemaVersion = "turn/v1"

// Turn sources and prompt modes, the wire vocabulary of turn/v1.
const (
	TurnSourceUserPrompt   = "user_prompt"
	TurnSourceSlashCommand = "slash_command"
	TurnSourceInterrupt    = "interrupt"

	TurnPromptOmitted = "omitted"
	TurnPromptExcerpt = "excerpt"
	TurnPromptSkipped = "skipped"
)

// turnTimeLayout is fixed-width UTC, so stored times order as text.
const turnTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

// TurnRecord is one turn as the hosted ledger receives it (turn/v1).
type TurnRecord struct {
	Schema    string     `json:"schema"`
	ID        string     `json:"id"`
	SessionID string     `json:"session_id"`
	Sequence  int64      `json:"sequence"`
	Agent     string     `json:"agent"`
	StartedAt string     `json:"started_at"`
	Source    string     `json:"source"`
	Prompt    TurnPrompt `json:"prompt"`
}

// TurnPrompt is what a turn says about its prompt. Size-only modes carry
// Chars alone; only an excerpt carries text, truncation and hash. Build it
// with SizeOnlyTurnPrompt or ExcerptTurnPrompt.
type TurnPrompt struct {
	Mode      string  `json:"mode"`
	Text      *string `json:"text,omitempty"`
	Chars     int64   `json:"chars"`
	Truncated *bool   `json:"truncated,omitempty"`
	SHA256    *string `json:"sha256,omitempty"`
}

// SizeOnlyTurnPrompt describes a prompt by its length alone (omitted or
// skipped).
func SizeOnlyTurnPrompt(mode string, chars int64) TurnPrompt {
	return TurnPrompt{Mode: mode, Chars: chars}
}

// ExcerptTurnPrompt carries a redacted, bounded excerpt.
func ExcerptTurnPrompt(text string, chars int64, truncated bool, sha256 string) TurnPrompt {
	return TurnPrompt{Mode: TurnPromptExcerpt, Text: &text, Chars: chars, Truncated: &truncated, SHA256: &sha256}
}

// FormatTurnTime renders a turn timestamp as stored and sent.
func FormatTurnTime(at time.Time) string {
	return at.UTC().Format(turnTimeLayout)
}

// SaveTurn stores a minted turn once; saving the same id again does nothing.
// The sequence is the session's next, taken in the same statement, so it
// needs no read on the hook path and survives a daemon restart.
func (s *Store) SaveTurn(ctx context.Context, turn TurnRecord) error {
	if turn.ID == "" || turn.SessionID == "" || turn.StartedAt == "" {
		return errors.New("turn requires id, session and start time")
	}
	var text, sha256 any
	truncated := false
	if turn.Prompt.Mode == TurnPromptExcerpt {
		if turn.Prompt.Text == nil || turn.Prompt.SHA256 == nil || turn.Prompt.Truncated == nil {
			return errors.New("turn excerpt requires text, hash and truncation")
		}
		text, sha256, truncated = *turn.Prompt.Text, *turn.Prompt.SHA256, *turn.Prompt.Truncated
	}
	_, err := s.db.ExecContext(ctx, `insert or ignore into turns(id, session_id, sequence, agent, started_at, source, prompt_mode, prompt_text, prompt_chars, prompt_sha256, prompt_truncated)
 select ?, ?, coalesce(max(sequence), 0) + 1, ?, ?, ?, ?, ?, ?, ?, ? from turns where session_id = ?`,
		turn.ID, turn.SessionID, turn.Agent, turn.StartedAt, turn.Source, turn.Prompt.Mode, text, turn.Prompt.Chars, sha256, truncated, turn.SessionID)
	return err
}

// CurrentTurn returns the id of the session's turn in progress at the given
// time, the latest one started at or before it, or "" when there is none.
func (s *Store) CurrentTurn(ctx context.Context, sessionID string, at time.Time) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `select id from turns where session_id = ? and started_at <= ? order by started_at desc, sequence desc limit 1`,
		NormalizeSessionID(sessionID), FormatTurnTime(at)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}

// TurnsForSession returns the session's minted turns, oldest first, without
// their prompts.
func (s *Store) TurnsForSession(ctx context.Context, sessionID string) ([]modelusage.Turn, error) {
	rows, err := s.db.QueryContext(ctx, `select id, started_at from turns where session_id = ? order by started_at, sequence`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var turns []modelusage.Turn
	for rows.Next() {
		var turn modelusage.Turn
		var startedAt string
		if err := rows.Scan(&turn.ID, &startedAt); err != nil {
			return nil, err
		}
		if turn.StartedAt, err = time.Parse(time.RFC3339Nano, startedAt); err != nil {
			return nil, fmt.Errorf("turn %s: invalid start time", turn.ID)
		}
		turns = append(turns, turn)
	}
	return turns, rows.Err()
}

// PendingTurns returns up to limit turns not yet acknowledged by the hosted
// ledger, oldest first.
func (s *Store) PendingTurns(ctx context.Context, limit int) ([]TurnRecord, error) {
	rows, err := s.db.QueryContext(ctx, `select id, session_id, sequence, agent, started_at, source, prompt_mode, prompt_text, prompt_chars, prompt_sha256, prompt_truncated
 from turns where exported = 0 order by started_at, id limit ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var turns []TurnRecord
	for rows.Next() {
		turn := TurnRecord{Schema: TurnSchemaVersion}
		var mode string
		var text, sha256 sql.NullString
		var chars int64
		var truncated bool
		if err := rows.Scan(&turn.ID, &turn.SessionID, &turn.Sequence, &turn.Agent, &turn.StartedAt, &turn.Source, &mode, &text, &chars, &sha256, &truncated); err != nil {
			return nil, err
		}
		if mode == TurnPromptExcerpt {
			turn.Prompt = ExcerptTurnPrompt(text.String, chars, truncated, sha256.String)
		} else {
			turn.Prompt = SizeOnlyTurnPrompt(mode, chars)
		}
		turns = append(turns, turn)
	}
	return turns, rows.Err()
}

// AcknowledgeTurns marks turns the hosted ledger has answered for.
func (s *Store) AcknowledgeTurns(ctx context.Context, ids []string) error {
	for _, chunk := range stringChunks(uniqueStrings(ids)) {
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		if _, err := s.db.ExecContext(ctx, `update turns set exported = 1 where id in (`+strings.TrimRight(strings.Repeat("?,", len(chunk)), ",")+`)`, args...); err != nil {
			return err
		}
	}
	return nil
}

// UsageRevisitWindow is how long after its last hook a transcript is read
// again for late usage. A turn is kept while any transcript of its session
// may still be read, since every read stamps the session's usage again.
const UsageRevisitWindow = 7 * 24 * time.Hour

// PruneExportedTurns deletes up to limit exported turns, and transcript turn
// boundaries, older than olderThan whose session has no transcript the usage
// reader may still revisit. It never deletes an unexported turn.
func (s *Store) PruneExportedTurns(ctx context.Context, olderThan time.Time, limit int) (int, error) {
	if limit <= 0 || olderThan.IsZero() {
		return 0, nil
	}
	cutoff := FormatTurnTime(olderThan)
	revisitFrom := time.Now().UTC().Add(-UsageRevisitWindow).Format(time.RFC3339Nano)
	// Mirrors toolUsageSources: a source is revisited while last_seen is
	// recent, or until its first successful read.
	const revisited = `exists(select 1 from tool_usage_sources s where s.session_id = %s.session_id and (s.last_seen >= ? or s.fingerprint = ''))`
	result, err := s.db.ExecContext(ctx, `delete from turns where rowid in (select t.rowid from turns t where t.exported = 1 and t.started_at < ? and not `+fmt.Sprintf(revisited, "t")+` order by t.started_at limit ?)`,
		cutoff, revisitFrom, limit)
	if err != nil {
		return 0, err
	}
	pruned, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if _, err := s.db.ExecContext(ctx, `delete from tool_usage_prompts where rowid in (select p.rowid from tool_usage_prompts p where p.started_at < ? and not `+fmt.Sprintf(revisited, "p")+` order by p.started_at limit ?)`,
		cutoff, revisitFrom, limit); err != nil {
		return int(pruned), err
	}
	return int(pruned), nil
}

// toolUsagePrompts returns the turn boundaries stored for a session, keyed
// by Unix nanoseconds.
func (s *Store) toolUsagePrompts(ctx context.Context, sessionID string) (map[int64]time.Time, error) {
	rows, err := s.db.QueryContext(ctx, `select started_at from tool_usage_prompts where session_id = ?`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	prompts := map[int64]time.Time{}
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		if at, err := time.Parse(time.RFC3339Nano, value); err == nil {
			prompts[at.UnixNano()] = at
		}
	}
	return prompts, rows.Err()
}

// assignToolUsageTurns stamps the records read in this pass with their
// minted turns. A session's turn boundaries are those of all its
// transcripts, stored by earlier passes or read in this one: a subagent's
// transcript has none of its own, and is often first read in the same pass
// as the parent prompt it runs under.
func (s *Store) assignToolUsageTurns(ctx context.Context, updates []toolUsageUpdate) error {
	bySession := map[string][]int{}
	var order []string
	for i, update := range updates {
		if !update.read || update.message != "" {
			continue
		}
		session := update.source.session
		if bySession[session] == nil {
			order = append(order, session)
		}
		bySession[session] = append(bySession[session], i)
	}
	for _, session := range order {
		known, err := s.toolUsagePrompts(ctx, session)
		if err != nil {
			return err
		}
		for _, i := range bySession[session] {
			for _, at := range updates[i].prompts {
				if _, ok := known[at.UnixNano()]; !ok {
					known[at.UnixNano()] = at
					updates[i].newPrompts = append(updates[i].newPrompts, at)
				}
			}
		}
		prompts := make([]time.Time, 0, len(known))
		for _, at := range known {
			prompts = append(prompts, at)
		}
		turns, err := s.TurnsForSession(ctx, session)
		if err != nil {
			return err
		}
		for _, i := range bySession[session] {
			modelusage.AssignTurns(updates[i].records, prompts, turns)
		}
	}
	return nil
}
