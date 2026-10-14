package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/modelusage"
)

const toolUsageDDL = `
create table if not exists tool_usage_sources (
 session_id text not null, transcript_path text not null, agent text not null,
 last_seen text not null, checked_at text not null default '',
 fingerprint text not null default '', error text not null default '',
 error_fingerprint text not null default '',
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
	// transcriptCursorIdle is how long a transcript's parser state is kept
	// without a change. A session idle for longer costs one full read when it
	// resumes.
	transcriptCursorIdle = 10 * time.Minute
	// transcriptTailBytes of the parsed prefix are compared before resuming.
	transcriptTailBytes = 64
)

type toolUsageSource struct {
	session, path, agent, lastSeen, checkedAt, fingerprint, message string
	// errorFingerprint is the file state whose read last failed.
	errorFingerprint string
}

// toolUsageUpdate is the outcome of one source in a reconcile pass, applied
// together with the other outcomes in a single short write transaction.
type toolUsageUpdate struct {
	source      toolUsageSource
	retire      bool
	read        bool
	fingerprint string
	message     string
	// attempted is the file state seen when the read was scheduled.
	attempted        string
	errorFingerprint string
	records          []modelusage.Record
}

// ReconcileToolUsage retries delayed/incomplete transcript writes and resumes
// after daemon restart using registered sources. Completed sources are
// revisited for seven days. Every pass stats each eligible source, but only
// parses transcripts whose size or mtime changed, oldest read first and
// bounded per pass, and of those only the lines appended since the previous
// pass; a transcript whose last read failed waits for a change or the retry
// interval. Unchanged sources cost no database write: this runs every flush
// interval, and rewriting each source's row per pass dominated the daemon's
// WAL traffic.
func (s *Store) ReconcileToolUsage(ctx context.Context) error {
	now := time.Now().UTC()
	sources, err := s.toolUsageSources(ctx, now)
	if err != nil {
		return err
	}
	var updates, pending []toolUsageUpdate
	for _, src := range sources {
		fingerprint, statErr := transcriptFingerprint(src.path)
		switch {
		case errors.Is(statErr, fs.ErrNotExist) && missingSince(src.lastSeen, now) > missingTranscriptGrace:
			updates = append(updates, toolUsageUpdate{source: src, retire: true})
		case statErr != nil:
			if statErr.Error() != src.message {
				updates = append(updates, toolUsageUpdate{source: src, fingerprint: src.fingerprint, message: statErr.Error()})
			}
		case fingerprint != src.fingerprint:
			// A failed read waits for the file to change or for the retry
			// interval. Comparing whole fingerprints, not mtimes, also sees a
			// size change on filesystems with coarse timestamps.
			if src.message == "" || fingerprint != src.errorFingerprint || retryDue(src.checkedAt, now) {
				pending = append(pending, toolUsageUpdate{source: src, attempted: fingerprint})
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
		fingerprint, records, readErr := readToolTranscript(update.source, now)
		if readErr != nil {
			update.fingerprint, update.message, update.errorFingerprint = update.source.fingerprint, readErr.Error(), update.attempted
		} else {
			update.fingerprint, update.records = fingerprint, records
		}
		updates = append(updates, update)
	}
	transcriptCursors.evict(now)
	return s.applyToolUsageUpdates(ctx, updates, now)
}

func (s *Store) toolUsageSources(ctx context.Context, now time.Time) ([]toolUsageSource, error) {
	rows, err := s.db.QueryContext(ctx, `select session_id, transcript_path, agent, last_seen, checked_at, fingerprint, error, error_fingerprint from tool_usage_sources
 where last_seen >= ? or fingerprint = ''`, now.Add(-7*24*time.Hour).Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sources []toolUsageSource
	for rows.Next() {
		var src toolUsageSource
		if err := rows.Scan(&src.session, &src.path, &src.agent, &src.lastSeen, &src.checkedAt, &src.fingerprint, &src.message, &src.errorFingerprint); err != nil {
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

// retryDue reports whether an unchanged source whose last read failed is
// due for another attempt.
func retryDue(checkedAt string, now time.Time) bool {
	checked, err := time.Parse(time.RFC3339Nano, checkedAt)
	return err != nil || now.Sub(checked) >= toolUsageRetryInterval
}

func transcriptFingerprint(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	return fingerprintTranscript(info)
}

// Re-read existing active sources once when the metadata adapter changes.
// Stable request IDs replace the old snapshots rather than adding usage.
func fingerprintTranscript(info fs.FileInfo) (string, error) {
	if !info.Mode().IsRegular() || info.Size() > maxTranscriptBytes {
		return "", fmt.Errorf("usage transcript must be a regular file up to 256 MiB")
	}
	// v4: Codex sub-agent records carry their root session, so rollouts read
	// before that, whose records were dropped, are read once more.
	return fmt.Sprintf("tool-metadata-v4:%d:%d", info.Size(), info.ModTime().UnixNano()), nil
}

// readToolTranscript parses a transcript without touching the database, so
// no write lock is held during file I/O. The returned fingerprint describes
// the file that was actually read. Every record a full read would return is
// returned, so unchanged ones keep their revision through
// saveChangedToolUsage.
func readToolTranscript(src toolUsageSource, now time.Time) (string, []modelusage.Record, error) {
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
	key := transcriptKey{codex: src.agent == "codex", path: src.path}
	cursor := transcriptCursors.take(key)
	if !cursor.resumes(f, stat) {
		cursor = &transcriptCursor{transcript: modelusage.NewClaudeTranscript()}
		if key.codex {
			cursor.transcript = modelusage.NewCodexTranscript()
		}
	}
	records, err := cursor.read(f, stat, now)
	transcriptCursors.put(key, cursor)
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

// transcriptCursors keeps recently changed transcripts' parser state between
// passes, so a pass parses only the lines appended since the previous one.
// Store handles are opened per flush, hence the package scope. The state is
// kept in memory rather than in tool_usage_sources: it holds every message's
// usage and tool metadata, hundreds of KB for a long session, and writing it
// on each pass would bring back the WAL traffic unchanged sources no longer
// cause. A daemon restart therefore costs one full read per changed source,
// and so does a metadata adapter upgrade, which ships as a new binary.
var transcriptCursors = transcriptCursorCache{cursors: map[transcriptKey]*transcriptCursor{}}

type transcriptKey struct {
	codex bool
	path  string
}

// transcriptCursor is a transcript's parser state after its last complete
// line, with what identifies the bytes it parsed.
type transcriptCursor struct {
	transcript *modelusage.Transcript
	file       fs.FileInfo // identity of the parsed file, for os.SameFile
	tail       []byte      // the parsed bytes just before the offset
	used       time.Time
}

// resumes reports whether f is still the file the cursor parsed, grown only by
// appends: the same file, no shorter, and with the bytes just before the
// offset unchanged. A replaced, truncated, or rewritten file is read again
// from the start. Transcripts are append-only, so earlier bytes are not
// compared.
func (c *transcriptCursor) resumes(f *os.File, stat fs.FileInfo) bool {
	if c == nil || !os.SameFile(c.file, stat) || stat.Size() < c.transcript.Offset() {
		return false
	}
	tail := make([]byte, len(c.tail))
	_, err := f.ReadAt(tail, c.transcript.Offset()-int64(len(tail)))
	return err == nil && bytes.Equal(tail, c.tail)
}

// read parses from the cursor's offset up to the fingerprinted size. A failed
// read still leaves the parser state at its last complete line.
func (c *transcriptCursor) read(f *os.File, stat fs.FileInfo, now time.Time) ([]modelusage.Record, error) {
	offset := c.transcript.Offset()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, err
	}
	records, err := c.transcript.Read(io.LimitReader(f, stat.Size()-offset))
	offset = c.transcript.Offset()
	c.file, c.used = stat, now
	c.tail = make([]byte, min(offset, transcriptTailBytes))
	if _, tailErr := f.ReadAt(c.tail, offset-int64(len(c.tail))); tailErr != nil {
		c.file = nil
	}
	return records, err
}

type transcriptCursorCache struct {
	mu      sync.Mutex
	cursors map[transcriptKey]*transcriptCursor
}

// take hands a cursor to one pass at a time. A concurrent pass over the same
// transcript starts from a full read instead of sharing parser state.
func (c *transcriptCursorCache) take(key transcriptKey) *transcriptCursor {
	c.mu.Lock()
	defer c.mu.Unlock()
	cursor := c.cursors[key]
	delete(c.cursors, key)
	return cursor
}

func (c *transcriptCursorCache) put(key transcriptKey, cursor *transcriptCursor) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cursors[key] = cursor
}

func (c *transcriptCursorCache) evict(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, cursor := range c.cursors {
		if now.Sub(cursor.used) > transcriptCursorIdle {
			delete(c.cursors, key)
		}
	}
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
		// The source row is written before any record is read. A deferred
		// transaction that reads first takes the write lock as an upgrade,
		// which SQLite refuses with SQLITE_BUSY at once instead of waiting
		// out busy_timeout.
		if update.read {
			_, err = tx.ExecContext(ctx, `update tool_usage_sources set checked_at=?, fingerprint=?, error=?, error_fingerprint=? where session_id=? and transcript_path=?`,
				checkedAt, update.fingerprint, update.message, update.errorFingerprint, src.session, src.path)
		} else {
			_, err = tx.ExecContext(ctx, `update tool_usage_sources set error=?, error_fingerprint='' where session_id=? and transcript_path=?`,
				update.message, src.session, src.path)
		}
		if err != nil {
			return err
		}
		if err := saveChangedToolUsage(ctx, tx, src, update.records); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// saveChangedToolUsage saves a source's records as saveToolUsage would, but
// issues no statement for a record already stored with the same agent and
// payload. A pass returns every record of the transcript, and a no-op upsert
// per record was most of a pass's CPU. The session's rows are read inside tx
// after its earlier writes and kept current with this source's own, so a
// record is compared with what saveToolUsage would see, including one that
// another transcript of the same session saved earlier in the pass.
func saveChangedToolUsage(ctx context.Context, tx *sql.Tx, src toolUsageSource, records []modelusage.Record) error {
	if len(records) == 0 {
		return nil
	}
	rows, err := tx.QueryContext(ctx, `select message_id, agent, payload from tool_usage_records where session_id=?`, src.session)
	if err != nil {
		return err
	}
	stored := map[toolUsageKey]toolUsageRow{}
	for rows.Next() {
		key, row := toolUsageKey{session: src.session}, toolUsageRow{}
		if err := rows.Scan(&key.message, &row.agent, &row.payload); err != nil {
			rows.Close()
			return err
		}
		stored[key] = row
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, record := range records {
		if !record.ToolRelated() {
			continue
		}
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		key, row := toolUsageKey{record.SessionID, record.MessageID}, toolUsageRow{src.agent, string(data)}
		if stored[key] == row {
			continue
		}
		if err := writeToolUsage(ctx, tx, key, row); err != nil {
			return err
		}
		stored[key] = row
	}
	return nil
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// toolUsageKey is a record's identity in tool_usage_records.
type toolUsageKey struct{ session, message string }

type toolUsageRow struct{ agent, payload string }

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
	return writeToolUsage(ctx, db, toolUsageKey{record.SessionID, record.MessageID}, toolUsageRow{agent, string(data)})
}

func writeToolUsage(ctx context.Context, db execer, key toolUsageKey, row toolUsageRow) error {
	// REPLACE allocates a fresh monotonically increasing revision only when
	// counters, associations, or agent metadata change. The agent comparison
	// detects a metadata correction; it does not identify a separate request.
	// A concurrent upload acknowledges its exact revision, so it cannot clear
	// a newer pending snapshot.
	_, err := db.ExecContext(ctx, `insert or replace into tool_usage_records(session_id,message_id,agent,payload)
 select ?,?,?,? where not exists(select 1 from tool_usage_records where session_id=? and message_id=? and agent=? and payload=?)`,
		key.session, key.message, row.agent, row.payload, key.session, key.message, row.agent, row.payload)
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
