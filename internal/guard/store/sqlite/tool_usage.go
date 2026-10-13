package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
 -- Match the cloud request identity. Agent is updatable metadata, not a key.
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

const (
	// toolUsageReadLimit bounds how many changed transcripts one pass parses.
	toolUsageReadLimit = 100
	// toolUsageRetryInterval is how often a transcript whose last read failed
	// is retried while the file itself stays unchanged.
	toolUsageRetryInterval = time.Hour
	// missingTranscriptGrace is how long a source may point at a missing file
	// before it is dropped. A live session re-registers on its next hook.
	missingTranscriptGrace = time.Hour
	maxTranscriptBytes     = 256 * 1024 * 1024
)

type toolUsageSource struct {
	session, path, agent, lastSeen, checkedAt, fingerprint, message string
}

// toolUsageUpdate is the outcome of one source in a reconcile pass, applied
// together with the other outcomes in a single short write transaction.
type toolUsageUpdate struct {
	source      toolUsageSource
	retire      bool
	read        bool
	fingerprint string
	message     string
	records     []modelusage.Record
}

// ReconcileToolUsage retries delayed/incomplete transcript writes and resumes
// after daemon restart using registered sources. Completed sources are
// revisited for seven days. Every pass stats each eligible source, but only
// parses transcripts whose size or mtime changed, oldest read first and
// bounded per pass; a transcript whose last read failed waits for a change
// or the retry interval. Unchanged sources cost no database write: this runs
// every flush interval, and rewriting each source's row per pass dominated
// the daemon's WAL traffic.
func (s *Store) ReconcileToolUsage(ctx context.Context) error {
	now := time.Now().UTC()
	sources, err := s.toolUsageSources(ctx, now)
	if err != nil {
		return err
	}
	var updates, pending []toolUsageUpdate
	for _, src := range sources {
		fingerprint, modTime, statErr := transcriptFingerprint(src.path)
		switch {
		case errors.Is(statErr, fs.ErrNotExist) && missingSince(src.lastSeen, now) > missingTranscriptGrace:
			updates = append(updates, toolUsageUpdate{source: src, retire: true})
		case statErr != nil:
			if statErr.Error() != src.message {
				updates = append(updates, toolUsageUpdate{source: src, fingerprint: src.fingerprint, message: statErr.Error()})
			}
		case fingerprint != src.fingerprint:
			if src.message == "" || retryDue(src.checkedAt, modTime, now) {
				pending = append(pending, toolUsageUpdate{source: src})
			}
		case src.message != "":
			// The transcript is readable again and was already imported.
			updates = append(updates, toolUsageUpdate{source: src, fingerprint: src.fingerprint})
		}
	}
	slices.SortStableFunc(pending, func(a, b toolUsageUpdate) int {
		return strings.Compare(a.source.checkedAt, b.source.checkedAt)
	})
	for _, update := range pending[:min(len(pending), toolUsageReadLimit)] {
		if err := ctx.Err(); err != nil {
			return err
		}
		update.read = true
		fingerprint, records, readErr := readToolTranscript(update.source)
		if readErr != nil {
			update.fingerprint, update.message = update.source.fingerprint, readErr.Error()
		} else {
			update.fingerprint, update.records = fingerprint, records
		}
		updates = append(updates, update)
	}
	return s.applyToolUsageUpdates(ctx, updates, now)
}

func (s *Store) toolUsageSources(ctx context.Context, now time.Time) ([]toolUsageSource, error) {
	rows, err := s.db.QueryContext(ctx, `select session_id, transcript_path, agent, last_seen, checked_at, fingerprint, error from tool_usage_sources
 where last_seen >= ? or fingerprint = ''`, now.Add(-7*24*time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []toolUsageSource
	for rows.Next() {
		var src toolUsageSource
		if err := rows.Scan(&src.session, &src.path, &src.agent, &src.lastSeen, &src.checkedAt, &src.fingerprint, &src.message); err != nil {
			return nil, err
		}
		sources = append(sources, src)
	}
	return sources, rows.Err()
}

// missingSince reports how long ago a source was last registered. An
// unparseable timestamp counts as just seen, so it is never dropped.
func missingSince(lastSeen string, now time.Time) time.Duration {
	seen, err := time.Parse(time.RFC3339Nano, lastSeen)
	if err != nil {
		return 0
	}
	return now.Sub(seen)
}

// retryDue reports whether a source whose last read failed should be read
// again: its file changed since that attempt, or the retry interval passed.
func retryDue(checkedAt string, modTime, now time.Time) bool {
	checked, err := time.Parse(time.RFC3339Nano, checkedAt)
	if err != nil {
		return true
	}
	return modTime.After(checked) || now.Sub(checked) >= toolUsageRetryInterval
}

func transcriptFingerprint(path string) (string, time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", time.Time{}, err
	}
	fingerprint, err := fingerprintTranscript(info)
	return fingerprint, info.ModTime(), err
}

// Re-read existing active sources once when the metadata adapter changes.
// Stable request IDs replace the old snapshots rather than adding usage.
func fingerprintTranscript(info fs.FileInfo) (string, error) {
	if !info.Mode().IsRegular() || info.Size() > maxTranscriptBytes {
		return "", fmt.Errorf("usage transcript must be a regular file up to 256 MiB")
	}
	return fmt.Sprintf("tool-metadata-v3:%d:%d", info.Size(), info.ModTime().UnixNano()), nil
}

// readToolTranscript parses a transcript without touching the database, so
// no write lock is held during file I/O. The returned fingerprint describes
// the file that was actually read.
func readToolTranscript(src toolUsageSource) (string, []modelusage.Record, error) {
	f, err := os.Open(src.path)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	fingerprint, err := fingerprintTranscript(stat)
	if err != nil {
		return "", nil, err
	}
	var records []modelusage.Record
	if src.agent == "codex" {
		records, err = modelusage.ReadCodexTranscript(f)
	} else {
		records, err = modelusage.ReadClaudeTranscript(f)
	}
	if err != nil {
		return "", nil, err
	}
	var kept []modelusage.Record
	for _, record := range records {
		// A hook may point at a parent/other session transcript. Never import
		// unrelated session usage through that path.
		if record.SessionID != src.session || !record.ToolRelated() {
			continue
		}
		if _, err := time.Parse(time.RFC3339Nano, record.Timestamp); err != nil {
			return "", nil, fmt.Errorf("usage message missing valid timestamp")
		}
		kept = append(kept, record)
	}
	return fingerprint, kept, nil
}

func (s *Store) applyToolUsageUpdates(ctx context.Context, updates []toolUsageUpdate, now time.Time) error {
	if len(updates) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	checkedAt := now.Format(time.RFC3339Nano)
	for _, update := range updates {
		src := update.source
		if update.retire {
			// A hook may have re-registered the source since the snapshot;
			// matching last_seen keeps that fresh registration.
			if _, err := tx.ExecContext(ctx, `delete from tool_usage_sources where session_id=? and transcript_path=? and last_seen=?`, src.session, src.path, src.lastSeen); err != nil {
				return err
			}
			continue
		}
		for _, record := range update.records {
			if err := saveToolUsage(ctx, tx, src.agent, record); err != nil {
				return err
			}
		}
		if update.read {
			_, err = tx.ExecContext(ctx, `update tool_usage_sources set checked_at=?, fingerprint=?, error=? where session_id=? and transcript_path=?`,
				checkedAt, update.fingerprint, update.message, src.session, src.path)
		} else {
			_, err = tx.ExecContext(ctx, `update tool_usage_sources set error=? where session_id=? and transcript_path=?`,
				update.message, src.session, src.path)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func (s *Store) SaveToolUsage(ctx context.Context, agent string, record modelusage.Record) error {
	return saveToolUsage(ctx, s.db, agent, record)
}

func saveToolUsage(ctx context.Context, db execer, agent string, record modelusage.Record) error {
	if !record.ToolRelated() {
		return nil
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	// REPLACE allocates a fresh monotonically increasing revision only when
	// counters, associations, or agent metadata change. The agent comparison
	// detects a metadata correction; it does not identify a separate request.
	// A concurrent upload acknowledges its exact revision, so it cannot clear
	// a newer pending snapshot.
	_, err = db.ExecContext(ctx, `insert or replace into tool_usage_records(session_id,message_id,agent,payload)
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
