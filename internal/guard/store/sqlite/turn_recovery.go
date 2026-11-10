package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kontext-security/kontext/internal/modelusage"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// Give the normal hook/recording queue time to finish before using a transcript
// fallback. Pending sources are revisited even if the file stops changing.
const turnRecoveryDelay = 5 * time.Second

type recoveryTarget struct {
	start time.Time
	end   time.Time
	id    string
}

func (s *Store) recoverSessionTurns(ctx context.Context, session string, updates []toolUsageUpdate, indices []int, prompts []time.Time, capture payloadcapture.RuntimeConfiguration, now time.Time, links map[string]string, present map[string]bool, hints map[int64]string) error {
	if !capture.Confirmed || !capture.WorkTypeClassification || capture.EffectiveMode == payloadcapture.ModeOmitted {
		return nil
	}
	slices.SortFunc(prompts, func(a, b time.Time) int { return a.Compare(b) })
	turns, err := s.TurnsForSession(ctx, session)
	if err != nil {
		return err
	}
	blocked := map[int64]bool{}
	rows, err := s.db.QueryContext(ctx, `select started_at from tool_usage_prompts where session_id=? and capture_allowed=0`, session)
	if err != nil {
		return err
	}
	for rows.Next() {
		var at string
		if err := rows.Scan(&at); err != nil {
			rows.Close()
			return err
		}
		value, e := time.Parse(time.RFC3339Nano, at)
		if e != nil {
			rows.Close()
			return e
		}
		blocked[value.UnixNano()] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rehydrate := map[string]bool{}
	rows, err = s.db.QueryContext(ctx, `select t.id from turns t where t.session_id=? and t.prompt_mode='skipped' and exists (
 select 1 from authorization_actions a where a.turn_id=t.id
 and json_extract(case when json_valid(a.context_json) then a.context_json else '{}' end,'$.hook_event_name')='UserPromptSubmit'
 and json_extract(case when json_valid(a.context_json) then a.context_json else '{}' end,'$.payload_capture.confirmed')=0)`, session)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		rehydrate[id] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	targets := map[int64]recoveryTarget{}
	for _, index := range indices {
		for _, record := range updates[index].records {
			if old := links[record.MessageID]; old != "" && !present[old] {
				continue
			}
			at, e := time.Parse(time.RFC3339Nano, record.Timestamp)
			if e != nil {
				continue
			}
			k := sort.Search(len(prompts), func(k int) bool { return prompts[k].After(at) }) - 1
			if k < 0 || blocked[prompts[k].UnixNano()] || hints[prompts[k].UnixNano()] != "" {
				continue
			}
			start := prompts[k]
			var end time.Time
			if k+1 < len(prompts) {
				end = prompts[k+1].Add(-modelusage.PromptHookSkew)
			}
			i := sort.Search(len(turns), func(i int) bool { return !turns[i].StartedAt.Before(start.Add(-modelusage.PromptHookSkew)) })
			id := ""
			if i < len(turns) && (end.IsZero() || turns[i].StartedAt.Before(end)) {
				id = turns[i].ID
				if !rehydrate[id] {
					continue
				}
			}
			if start.After(now.Add(-turnRecoveryDelay)) {
				updates[index].recoveryPending = true
				continue
			}
			targets[start.UnixNano()] = recoveryTarget{start, end, id}
		}
	}
	if len(targets) == 0 {
		return nil
	}
	for _, index := range indices {
		if err := ctx.Err(); err != nil {
			return err
		}
		found, err := readRecoveryPrompts(updates[index].source)
		if err != nil {
			updates[index].recoveryPending = true
			continue
		}
		for _, prompt := range found {
			if prompt.SessionID != session || prompt.Text == nil {
				continue
			}
			target, ok := targets[prompt.Timestamp.UnixNano()]
			if !ok {
				continue
			}
			captured := CaptureTurnPrompt(*prompt.Text, capture)
			if captured.Mode != TurnPromptExcerpt {
				continue
			}
			if target.id != "" {
				if err := s.restoreSkippedPrompt(ctx, target.id, captured); err != nil {
					return err
				}
			} else {
				source := TurnSourceUserPrompt
				if strings.HasPrefix(*prompt.Text, "/") {
					source = TurnSourceSlashCommand
				}
				id := "turn_" + uuid.NewSHA1(uuid.NameSpaceOID, []byte("kontext:transcript-turn:v1\n"+session+"\n"+FormatTurnTime(target.start))).String()
				record := TurnRecord{Schema: TurnSchemaVersion, ID: id, SessionID: session, Agent: updates[index].source.agent, StartedAt: FormatTurnTime(target.start), Source: source, Prompt: captured}
				if err := s.saveRecoveredTurn(ctx, record, target.start.Add(-modelusage.PromptHookSkew), target.end); err != nil {
					return err
				}
			}
			delete(targets, prompt.Timestamp.UnixNano())
		}
	}
	return nil
}

func (s *Store) storedToolUsageTurnLinks(ctx context.Context, session string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, `select message_id,json_extract(payload,'$.turn_id') from tool_usage_records where session_id=? and coalesce(json_extract(payload,'$.turn_id'),'')<>''`, session)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	links := map[string]string{}
	for rows.Next() {
		var message, id string
		if err := rows.Scan(&message, &id); err != nil {
			return nil, err
		}
		links[message] = id
	}
	return links, rows.Err()
}

// A fresh, short-lived parser retains prompt text only for this recovery pass.
// The normal cached metadata cursor never sees or retains it.
func readRecoveryPrompts(source toolUsageSource) ([]modelusage.Prompt, error) {
	f, err := os.Open(source.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > maxTranscriptBytes {
		return nil, errors.New("recovery transcript is not a bounded regular file")
	}
	reader := newToolTranscript(transcriptFormat(source.agent), source.session)
	reader.EnablePromptText()
	if _, err := reader.Read(io.LimitReader(f, maxTranscriptBytes+1)); err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("transcript changed during recovery")
	}
	return reader.Prompts(), nil
}

func (s *Store) saveRecoveredTurn(ctx context.Context, turn TurnRecord, from, to time.Time) error {
	end := ""
	if !to.IsZero() {
		end = FormatTurnTime(to)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `insert or ignore into turns(id,session_id,sequence,agent,started_at,source,prompt_mode,prompt_text,prompt_chars,prompt_sha256,prompt_truncated)
 select ?,?,coalesce(max(sequence),0)+1,?,?,?,?,?,?,?,? from turns where session_id=?
 having not exists(select 1 from turns where session_id=? and started_at>=? and (?='' or started_at<?))`,
		turn.ID, turn.SessionID, turn.Agent, turn.StartedAt, turn.Source, turn.Prompt.Mode, *turn.Prompt.Text, turn.Prompt.Chars, *turn.Prompt.SHA256, *turn.Prompt.Truncated,
		turn.SessionID, turn.SessionID, FormatTurnTime(from), end, end)
	if err != nil {
		return fmt.Errorf("save recovered turn: %w", err)
	}
	if count, err := result.RowsAffected(); err != nil {
		return err
	} else if count > 0 {
		if err := markToolUsageSourcesForRestamp(ctx, tx, turn.SessionID, nil); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) restoreSkippedPrompt(ctx context.Context, id string, prompt TurnPrompt) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var session string
	err = tx.QueryRowContext(ctx, `update turns set prompt_mode=?,prompt_text=?,prompt_chars=?,prompt_sha256=?,prompt_truncated=?,exported=0
 where id=? and prompt_mode='skipped' and prompt_text is null returning session_id`, prompt.Mode, *prompt.Text, prompt.Chars, *prompt.SHA256, *prompt.Truncated, id).Scan(&session)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := markToolUsageSourcesForRestamp(ctx, tx, session, nil); err != nil {
		return err
	}
	return tx.Commit()
}
