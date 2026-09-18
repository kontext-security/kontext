package sqlite

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/modelusage"
)

const toolUsageDDL = `
create table if not exists tool_usage_sources (
 session_id text not null, transcript_path text not null, agent text not null,
 last_seen text not null, checked_at text not null default '',
 fingerprint text not null default '', error text not null default '',
 primary key(session_id, transcript_path)
);
create table if not exists tool_usage_records (
 revision integer primary key autoincrement, session_id text not null,
 message_id text not null, agent text not null, payload text not null,
 exported integer not null default 0, unique(session_id, message_id)
);
create index if not exists tool_usage_pending on tool_usage_records(exported, revision);
`

// ToolUsageRecord carries counters and associations only, never transcript text.
type ToolUsageRecord struct {
	modelusage.Record
	Agent    string `json:"agent"`
	Revision int64  `json:"revision"`
}

// TrackToolTranscript only registers local metadata. Transcript I/O is done by
// the stream worker, outside the policy decision/acknowledgement path.
func (s *Store) TrackToolTranscript(ctx context.Context, event hook.Event) error {
	if event.Agent != "claude" && event.Agent != "cowork" && event.Agent != "codex" {
		return nil
	}
	if event.SessionID == "" {
		return nil
	}
	switch event.HookName {
	case hook.HookPostToolUse, hook.HookPostToolUseFailed, hook.HookStop, hook.HookSessionEnd, hook.HookSubagentStop:
	default:
		return nil
	}
	paths := []string{event.TranscriptPath}
	if event.HookName == hook.HookSubagentStop {
		paths = append(paths, event.AgentTranscriptPath)
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if !filepath.IsAbs(path) {
			return fmt.Errorf("usage transcript path must be absolute")
		}
		_, err := s.db.ExecContext(ctx, `insert into tool_usage_sources(session_id, transcript_path, agent, last_seen)
 values(?,?,?,?) on conflict(session_id, transcript_path) do update set last_seen=excluded.last_seen, agent=excluded.agent`,
			event.SessionID, path, event.Agent, time.Now().UTC().Format(time.RFC3339Nano))
		if err != nil {
			return err
		}
	}
	return nil
}

// ReconcileToolUsage retries delayed/incomplete transcript writes and resumes
// after daemon restart using registered sources. Each pass is bounded; oldest
// checked sources go first. Completed sources are revisited for seven days.
func (s *Store) ReconcileToolUsage(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `select session_id, transcript_path, agent, fingerprint from tool_usage_sources
 where last_seen >= ? or fingerprint = '' order by checked_at limit 100`, time.Now().Add(-7*24*time.Hour).UTC().Format(time.RFC3339Nano))
	if err != nil {
		return err
	}
	type source struct{ session, path, agent, fingerprint string }
	var sources []source
	for rows.Next() {
		var src source
		if err := rows.Scan(&src.session, &src.path, &src.agent, &src.fingerprint); err != nil {
			rows.Close()
			return err
		}
		sources = append(sources, src)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, src := range sources {
		if err := ctx.Err(); err != nil {
			return err
		}
		fingerprint, readErr := s.reconcileToolTranscript(ctx, src.session, src.path, src.agent, src.fingerprint)
		message := ""
		if readErr != nil {
			message = readErr.Error()
			fingerprint = src.fingerprint
		}
		if _, err := s.db.ExecContext(ctx, `update tool_usage_sources set checked_at=?, fingerprint=?, error=? where session_id=? and transcript_path=?`,
			time.Now().UTC().Format(time.RFC3339Nano), fingerprint, message, src.session, src.path); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) reconcileToolTranscript(ctx context.Context, session, path, agent, previous string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("usage transcript must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() || stat.Size() > 256*1024*1024 {
		return "", fmt.Errorf("usage transcript must be a regular file up to 256 MiB")
	}
	fingerprint := fmt.Sprintf("%d:%d", stat.Size(), stat.ModTime().UnixNano())
	if fingerprint == previous {
		return previous, nil
	}
	var records []modelusage.Record
	if agent == "codex" {
		records, err = modelusage.ReadCodexTranscript(f)
	} else {
		records, err = modelusage.ReadClaudeTranscript(f)
	}
	if err != nil {
		return "", err
	}
	for _, record := range records {
		// A hook may point at a parent/other session transcript. Never import
		// unrelated session usage through that path.
		if record.SessionID != session || !record.ToolRelated() {
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, record.Timestamp); err != nil {
			return "", fmt.Errorf("usage message missing valid timestamp")
		}
		if err := s.SaveToolUsage(ctx, agent, record); err != nil {
			return "", err
		}
	}
	return fingerprint, nil
}

func (s *Store) SaveToolUsage(ctx context.Context, agent string, record modelusage.Record) error {
	if !record.ToolRelated() {
		return nil
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	// REPLACE allocates a fresh monotonically increasing revision only when
	// counters/associations change. A concurrent upload acknowledges its exact
	// revision, so it cannot clear a newer pending snapshot.
	_, err = s.db.ExecContext(ctx, `insert or replace into tool_usage_records(session_id,message_id,agent,payload)
 select ?,?,?,? where not exists(select 1 from tool_usage_records where session_id=? and message_id=? and agent=? and payload=?)`,
		record.SessionID, record.MessageID, agent, string(data), record.SessionID, record.MessageID, agent, string(data))
	return err
}

func (s *Store) PendingToolUsage(ctx context.Context, limit int) ([]ToolUsageRecord, error) {
	rows, err := s.db.QueryContext(ctx, `select revision, agent, payload from tool_usage_records where exported=0 order by revision limit ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []ToolUsageRecord
	for rows.Next() {
		var r ToolUsageRecord
		var raw string
		if err := rows.Scan(&r.Revision, &r.Agent, &raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(raw), &r.Record); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (s *Store) AcknowledgeToolUsage(ctx context.Context, records []ToolUsageRecord) error {
	for _, record := range records {
		if _, err := s.db.ExecContext(ctx, `update tool_usage_records set exported=1 where revision=?`, record.Revision); err != nil {
			return err
		}
	}
	return nil
}
