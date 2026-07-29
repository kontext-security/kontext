package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/payloadcapture"
)

type Store struct {
	db     *sql.DB
	path   string
	signer receiptSigner

	// Capture configuration lives on Store so each persisted decision can
	// snapshot behavior and evidence atomically.
	captureMu     sync.RWMutex
	captureConfig payloadcapture.RuntimeConfiguration
}

func (s *Store) SetPayloadCaptureConfiguration(config payloadcapture.RuntimeConfiguration) {
	s.captureMu.Lock()
	defer s.captureMu.Unlock()
	s.captureConfig = payloadcapture.SafeRuntimeConfiguration(config)
}

func (s *Store) payloadCaptureConfiguration() payloadcapture.RuntimeConfiguration {
	s.captureMu.RLock()
	defer s.captureMu.RUnlock()
	if s.captureConfig.EffectiveMode == "" {
		return payloadcapture.DefaultRuntimeConfiguration()
	}
	return s.captureConfig
}

type DecisionRecord struct {
	ID            string         `json:"id"`
	SessionID     string         `json:"session_id"`
	ToolUseID     string         `json:"tool_use_id,omitempty"`
	HookEventName string         `json:"hook_event_name"`
	ToolName      string         `json:"tool_name,omitempty"`
	Decision      risk.Decision  `json:"decision"`
	ReasonCode    string         `json:"reason_code"`
	Reason        string         `json:"reason"`
	RiskScore     *float64       `json:"risk_score,omitempty"`
	Threshold     *float64       `json:"threshold,omitempty"`
	ModelVersion  string         `json:"model_version,omitempty"`
	RiskEvent     risk.RiskEvent `json:"risk_event"`
	CreatedAt     time.Time      `json:"created_at"`
}

type Summary struct {
	Critical int `json:"critical"`
	Warnings int `json:"warnings"`
	Actions  int `json:"actions"`
	Sessions int `json:"sessions"`
}

type SessionSummary struct {
	SessionID string     `json:"session_id"`
	Critical  int        `json:"critical"`
	Warnings  int        `json:"warnings"`
	Actions   int        `json:"actions"`
	LatestAt  time.Time  `json:"latest_at"`
	Status    string     `json:"status,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	ClosedAt  *time.Time `json:"closed_at,omitempty"`
	Current   bool       `json:"current,omitempty"`
	Mode      string     `json:"mode,omitempty"`
}

type SessionRecord struct {
	ID            string     `json:"id"`
	AgentProvider string     `json:"agent_provider,omitempty"`
	Agent         string     `json:"agent,omitempty"`
	CWD           string     `json:"cwd,omitempty"`
	Source        string     `json:"source,omitempty"`
	Status        string     `json:"status,omitempty"`
	ExternalID    string     `json:"external_id,omitempty"`
	Mode          string     `json:"mode,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	ClosedAt      *time.Time `json:"closed_at,omitempty"`
}

func OpenStore(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(context.Background(), "pragma busy_timeout = 5000"); err != nil {
		db.Close()
		return nil, err
	}
	signer, err := newReceiptSigner(path)
	if err != nil {
		db.Close()
		return nil, err
	}
	store := &Store{db: db, path: path, signer: signer}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
	create table if not exists agent_sessions (
		  id text primary key,
		  runtime_kind text,
		  runtime_instance_id text,
		  adapter_kind text,
		  adapter_version text,
		  agent_provider text,
		  agent text,
		  conversation_id text,
		  trace_id text,
		  principal_id text,
		  identity_context_json text,
		  identity_hash text,
		  policy_version text,
		  policy_hash text,
		  cwd text,
		  source text not null default 'daemon_observed',
		  status text not null default 'open',
		  external_id text,
		  mode text,
	  closed_at text,
	  created_at text not null,
	  updated_at text not null
	);

	create table if not exists authorization_actions (
	  id text primary key,
	  session_id text not null,
	  turn_id text,
	  tool_use_id text,
	  trace_id text,
	  span_id text,
	  parent_span_id text,

	  runtime_kind text,
	  runtime_instance_id text,
	  adapter_kind text,
	  adapter_version text,
	  canonical_event_type text not null,
	  adapter_event_name text,
	  correlation_key text,
	  correlation_confidence real,

	  tool_name text,
	  provider text,
	  operation text,
	  operation_class text,
	  resource_class text,
	  resource_id text,
	  parameters_redacted_json text not null default '{}',
	  parameters_hash text,

	  identity_context_json text not null default '{}',
	  identity_hash text,
	  context_json text not null default '{}',
	  context_hash text,

	  policy_id text,
	  policy_version text,
	  policy_hash text,
	  default_posture text,

		  decision_result text,
	  decision_category text,
	  adapter_decision text,
	  reason_code text,
	  reason text,

	  schema_version text,
	  tool_call_id text,
	  applied_mode text,
	  evaluation_state text,
	  cedar_action text,
	  decision_fact_json text,

	  risk_level text,
	  risk_score real,
	  risk_threshold real,
	  model_version text,
	  compositional_risk_score real,
	  confidence real,
	  alignment_score real,
	  alignment_threshold real,
	  uncertainty_score real,
	  matched_rules_json text not null default '[]',
	  risk_signals_json text not null default '[]',
	  risk_event_json text not null default '{}',

	  modifications_json text not null default '{}',
	  approval_context_json text not null default '{}',
	  approval_channel text,
	  approval_request_id text,
	  approval_expires_at text,
	  deferral_context_json text not null default '{}',

	  status text not null,
	  outcome text,
	  output_summary text,
	  output_hash text,
	  error_redacted text,
	  tool_input_captured_json text,
	  tool_output_captured_json text,

	  proposed_at text,
	  decision_at text,
	  completed_at text,
	  created_at text not null,
	  updated_at text not null,
	  updated_at_cursor_key text not null default ''
	);

	create table if not exists authorization_receipts (
	  id text primary key,
	  action_id text not null,
	  session_id text not null,
	  receipt_type text not null,

	  decision_result text,
	  decision_category text,
	  reason_code text,

	  approval_channel text,
	  approval_result text,
	  approver_id text,
	  approved_at text,

	  policy_hash text,
	  context_hash text,
	  identity_hash text,
	  risk_evaluation_hash text,
	  action_hash text,
	  outcome_hash text,

	  receipt_payload_json text not null,
	  previous_receipt_hash text,
	  receipt_hash text not null,
	  signature text,
	  signature_algorithm text,
	  key_id text,

	  created_at text not null
	);

	create index if not exists idx_authorization_receipts_action_created
	on authorization_receipts(action_id, created_at);
		`)
	if err != nil {
		return err
	}
	if err := s.ensureAuthorizationActionsDecisionNullable(ctx); err != nil {
		return err
	}
	if err := s.ensureColumn(ctx, "authorization_actions", "updated_at_cursor_key", "text not null default ''"); err != nil {
		return err
	}
	// Decision Fact v1 mirror columns: written only on new request.decided
	// rows; historical rows keep nulls and remain on the legacy read paths.
	for _, column := range []string{
		"schema_version", "tool_call_id",
		"applied_mode", "evaluation_state", "cedar_action", "decision_fact_json",
	} {
		if err := s.ensureColumn(ctx, "authorization_actions", column, "text"); err != nil {
			return err
		}
	}
	if err := s.backfillAuthorizationActionCursorKeys(ctx); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `
	create index if not exists idx_authorization_actions_session_updated
	on authorization_actions(session_id, updated_at);

	create index if not exists idx_authorization_actions_cursor
	on authorization_actions(updated_at_cursor_key, id);

	create index if not exists idx_authorization_actions_session_tool_use
	on authorization_actions(session_id, tool_use_id);
	`); err != nil {
		return err
	}
	for _, column := range []struct {
		name string
		def  string
	}{
		{name: "runtime_kind", def: "text"},
		{name: "runtime_instance_id", def: "text"},
		{name: "adapter_kind", def: "text"},
		{name: "adapter_version", def: "text"},
		{name: "agent_provider", def: "text"},
		{name: "conversation_id", def: "text"},
		{name: "trace_id", def: "text"},
		{name: "principal_id", def: "text"},
		{name: "identity_context_json", def: "text"},
		{name: "identity_hash", def: "text"},
		{name: "policy_version", def: "text"},
		{name: "policy_hash", def: "text"},
		{name: "source", def: "text not null default 'daemon_observed'"},
		{name: "status", def: "text not null default 'open'"},
		{name: "external_id", def: "text"},
		{name: "mode", def: "text"},
		{name: "closed_at", def: "text"},
	} {
		if err := s.ensureColumn(ctx, "agent_sessions", column.name, column.def); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureColumn(ctx context.Context, table, name, def string) error {
	rows, err := s.db.QueryContext(ctx, "pragma table_info("+table+")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var columnName, columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if columnName == name {
			return rows.Err()
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, fmt.Sprintf("alter table %s add column %s %s", table, name, def))
	return err
}

func (s *Store) ensureAuthorizationActionsDecisionNullable(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "pragma table_info(authorization_actions)")
	if err != nil {
		return err
	}
	defer rows.Close()

	existingColumns := map[string]bool{}
	decisionResultNotNull := false
	for rows.Next() {
		var cid int
		var columnName, columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		if err := rows.Scan(&cid, &columnName, &columnType, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		existingColumns[columnName] = true
		if columnName == "decision_result" {
			decisionResultNotNull = notNull == 1
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	needsRebuild := decisionResultNotNull
	for _, column := range authorizationActionColumns {
		if !existingColumns[column.name] {
			needsRebuild = true
			break
		}
	}
	if !needsRebuild {
		return nil
	}

	_, err = s.db.ExecContext(ctx, fmt.Sprintf(`
	alter table authorization_actions rename to authorization_actions_legacy_not_null;

	create table authorization_actions (
	  id text primary key,
	  session_id text not null,
	  turn_id text,
	  tool_use_id text,
	  trace_id text,
	  span_id text,
	  parent_span_id text,

	  runtime_kind text,
	  runtime_instance_id text,
	  adapter_kind text,
	  adapter_version text,
	  canonical_event_type text not null,
	  adapter_event_name text,
	  correlation_key text,
	  correlation_confidence real,

	  tool_name text,
	  provider text,
	  operation text,
	  operation_class text,
	  resource_class text,
	  resource_id text,
	  parameters_redacted_json text not null default '{}',
	  parameters_hash text,

	  identity_context_json text not null default '{}',
	  identity_hash text,
	  context_json text not null default '{}',
	  context_hash text,

	  policy_id text,
	  policy_version text,
	  policy_hash text,
	  default_posture text,

	  decision_result text,
	  decision_category text,
	  adapter_decision text,
	  reason_code text,
	  reason text,

	  schema_version text,
	  tool_call_id text,
	  applied_mode text,
	  evaluation_state text,
	  cedar_action text,
	  decision_fact_json text,

	  risk_level text,
	  risk_score real,
	  risk_threshold real,
	  model_version text,
	  compositional_risk_score real,
	  confidence real,
	  alignment_score real,
	  alignment_threshold real,
	  uncertainty_score real,
	  matched_rules_json text not null default '[]',
	  risk_signals_json text not null default '[]',
	  risk_event_json text not null default '{}',

	  modifications_json text not null default '{}',
	  approval_context_json text not null default '{}',
	  approval_channel text,
	  approval_request_id text,
	  approval_expires_at text,
	  deferral_context_json text not null default '{}',

	  status text not null,
	  outcome text,
	  output_summary text,
	  output_hash text,
	  error_redacted text,
	  tool_input_captured_json text,
	  tool_output_captured_json text,

	  proposed_at text,
	  decision_at text,
	  completed_at text,
	  created_at text not null,
	  updated_at text not null,
	  updated_at_cursor_key text not null default ''
	);

	insert into authorization_actions (
	  %s
	)
	select
	  %s
	from authorization_actions_legacy_not_null;

	drop table authorization_actions_legacy_not_null;

	create index if not exists idx_authorization_actions_session_updated
	on authorization_actions(session_id, updated_at);

	create index if not exists idx_authorization_actions_cursor
	on authorization_actions(updated_at_cursor_key, id);

	create index if not exists idx_authorization_actions_session_tool_use
	on authorization_actions(session_id, tool_use_id);
	`, authorizationActionInsertColumns(), authorizationActionSelectExpressions(existingColumns)))
	return err
}

type authorizationActionColumn struct {
	name        string
	copyExpr    string
	defaultExpr string
}

const (
	migrateCanonicalEventTypeExpr = "case coalesce(canonical_event_type, '') when 'action.proposed' then 'request.decided' when 'action.completed' then 'request.observed' when 'action.failed' then 'request.failed' else coalesce(canonical_event_type, 'request.decided') end"
	migrateDecisionResultExpr     = "case lower(coalesce(decision_result, '')) when 'allow' then 'allow' when 'deny' then 'deny' when 'ask' then 'deny' else null end"
)

var authorizationActionColumns = []authorizationActionColumn{
	{name: "id", copyExpr: "coalesce(id, lower(hex(randomblob(16))))", defaultExpr: "lower(hex(randomblob(16)))"},
	{name: "session_id", copyExpr: "coalesce(session_id, '')", defaultExpr: "''"},
	{name: "turn_id", defaultExpr: "null"},
	{name: "tool_use_id", defaultExpr: "null"},
	{name: "trace_id", defaultExpr: "null"},
	{name: "span_id", defaultExpr: "null"},
	{name: "parent_span_id", defaultExpr: "null"},
	{name: "runtime_kind", defaultExpr: "null"},
	{name: "runtime_instance_id", defaultExpr: "null"},
	{name: "adapter_kind", defaultExpr: "null"},
	{name: "adapter_version", defaultExpr: "null"},
	{name: "canonical_event_type", copyExpr: migrateCanonicalEventTypeExpr, defaultExpr: "'request.decided'"},
	{name: "adapter_event_name", defaultExpr: "null"},
	{name: "correlation_key", defaultExpr: "null"},
	{name: "correlation_confidence", defaultExpr: "null"},
	{name: "tool_name", defaultExpr: "null"},
	{name: "provider", defaultExpr: "null"},
	{name: "operation", defaultExpr: "null"},
	{name: "operation_class", defaultExpr: "null"},
	{name: "resource_class", defaultExpr: "null"},
	{name: "resource_id", defaultExpr: "null"},
	{name: "parameters_redacted_json", copyExpr: "coalesce(parameters_redacted_json, '{}')", defaultExpr: "'{}'"},
	{name: "parameters_hash", defaultExpr: "null"},
	{name: "identity_context_json", copyExpr: "coalesce(identity_context_json, '{}')", defaultExpr: "'{}'"},
	{name: "identity_hash", defaultExpr: "null"},
	{name: "context_json", copyExpr: "coalesce(context_json, '{}')", defaultExpr: "'{}'"},
	{name: "context_hash", defaultExpr: "null"},
	{name: "policy_id", defaultExpr: "null"},
	{name: "policy_version", defaultExpr: "null"},
	{name: "policy_hash", defaultExpr: "null"},
	{name: "default_posture", defaultExpr: "null"},
	{name: "decision_result", copyExpr: migrateDecisionResultExpr, defaultExpr: "null"},
	{name: "decision_category", defaultExpr: "null"},
	{name: "adapter_decision", defaultExpr: "null"},
	{name: "reason_code", defaultExpr: "null"},
	{name: "reason", defaultExpr: "null"},
	{name: "schema_version", defaultExpr: "null"},
	{name: "tool_call_id", defaultExpr: "null"},
	{name: "applied_mode", defaultExpr: "null"},
	{name: "evaluation_state", defaultExpr: "null"},
	{name: "cedar_action", defaultExpr: "null"},
	{name: "decision_fact_json", defaultExpr: "null"},
	{name: "risk_level", defaultExpr: "null"},
	{name: "risk_score", defaultExpr: "null"},
	{name: "risk_threshold", defaultExpr: "null"},
	{name: "model_version", defaultExpr: "null"},
	{name: "compositional_risk_score", defaultExpr: "null"},
	{name: "confidence", defaultExpr: "null"},
	{name: "alignment_score", defaultExpr: "null"},
	{name: "alignment_threshold", defaultExpr: "null"},
	{name: "uncertainty_score", defaultExpr: "null"},
	{name: "matched_rules_json", copyExpr: "coalesce(matched_rules_json, '[]')", defaultExpr: "'[]'"},
	{name: "risk_signals_json", copyExpr: "coalesce(risk_signals_json, '[]')", defaultExpr: "'[]'"},
	{name: "risk_event_json", copyExpr: "coalesce(risk_event_json, '{}')", defaultExpr: "'{}'"},
	{name: "modifications_json", copyExpr: "coalesce(modifications_json, '{}')", defaultExpr: "'{}'"},
	{name: "approval_context_json", copyExpr: "coalesce(approval_context_json, '{}')", defaultExpr: "'{}'"},
	{name: "approval_channel", defaultExpr: "null"},
	{name: "approval_request_id", defaultExpr: "null"},
	{name: "approval_expires_at", defaultExpr: "null"},
	{name: "deferral_context_json", copyExpr: "coalesce(deferral_context_json, '{}')", defaultExpr: "'{}'"},
	{name: "status", copyExpr: "coalesce(status, 'authorized')", defaultExpr: "'authorized'"},
	{name: "outcome", defaultExpr: "null"},
	{name: "output_summary", defaultExpr: "null"},
	{name: "output_hash", defaultExpr: "null"},
	{name: "error_redacted", defaultExpr: "null"},
	{name: "tool_input_captured_json", defaultExpr: "null"},
	{name: "tool_output_captured_json", defaultExpr: "null"},
	{name: "proposed_at", defaultExpr: "null"},
	{name: "decision_at", defaultExpr: "null"},
	{name: "completed_at", defaultExpr: "null"},
	{name: "created_at", copyExpr: "coalesce(created_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))", defaultExpr: "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"},
	{name: "updated_at", copyExpr: "coalesce(updated_at, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))", defaultExpr: "strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"},
	{name: "updated_at_cursor_key", copyExpr: "coalesce(updated_at_cursor_key, '')", defaultExpr: "''"},
}

func authorizationActionInsertColumns() string {
	names := make([]string, 0, len(authorizationActionColumns))
	for _, column := range authorizationActionColumns {
		names = append(names, column.name)
	}
	return strings.Join(names, ",\n\t  ")
}

func authorizationActionSelectExpressions(existingColumns map[string]bool) string {
	expressions := make([]string, 0, len(authorizationActionColumns))
	for _, column := range authorizationActionColumns {
		expr := column.defaultExpr
		if existingColumns[column.name] {
			expr = column.name
			if column.copyExpr != "" {
				expr = column.copyExpr
			}
		}
		expressions = append(expressions, fmt.Sprintf("%s as %s", expr, column.name))
	}
	return strings.Join(expressions, ",\n\t  ")
}

func (s *Store) backfillAuthorizationActionCursorKeys(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `
select id, updated_at, created_at, updated_at_cursor_key
from authorization_actions
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type cursorKeyUpdate struct {
		id  string
		key string
	}
	updates := []cursorKeyUpdate{}
	for rows.Next() {
		var id, updatedAt, createdAt, currentKey string
		if err := rows.Scan(&id, &updatedAt, &createdAt, &currentKey); err != nil {
			return err
		}
		key := ledgerTimestampCursorKeyFromValues(updatedAt, createdAt)
		if currentKey == key {
			continue
		}
		updates = append(updates, cursorKeyUpdate{id: id, key: key})
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, update := range updates {
		if _, err := s.db.ExecContext(ctx, `
update authorization_actions
set updated_at_cursor_key = ?
where id = ?
		`, update.key, update.id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) OpenSession(ctx context.Context, sessionID, agent, cwd, source, externalID string) (SessionRecord, error) {
	return s.OpenSessionWithMode(ctx, sessionID, agent, cwd, source, externalID, "")
}

func (s *Store) OpenSessionWithMode(ctx context.Context, sessionID, agent, cwd, source, externalID, mode string) (SessionRecord, error) {
	now := time.Now().UTC()
	sessionID = normalizeSessionID(sessionID)
	agentProvider, canonicalAgent := hostedAgentIdentity(agent)
	if source == "" {
		source = "daemon_observed"
	}
	_, err := s.db.ExecContext(ctx, `
insert into agent_sessions(id, agent_provider, agent, cwd, source, status, external_id, mode, closed_at, created_at, updated_at)
values(?, ?, ?, ?, ?, 'open', ?, ?, null, ?, ?)
on conflict(id) do update set
  agent_provider = coalesce(nullif(excluded.agent_provider, ''), agent_sessions.agent_provider),
  agent = coalesce(nullif(excluded.agent, ''), agent_sessions.agent),
  cwd = coalesce(nullif(excluded.cwd, ''), agent_sessions.cwd),
  source = case
    when excluded.source = 'wrapper_owned' then excluded.source
    when agent_sessions.source = 'wrapper_owned' then agent_sessions.source
    else coalesce(nullif(excluded.source, ''), agent_sessions.source)
  end,
  status = 'open',
  external_id = coalesce(nullif(excluded.external_id, ''), agent_sessions.external_id),
  mode = coalesce(nullif(excluded.mode, ''), agent_sessions.mode),
  closed_at = null,
  updated_at = excluded.updated_at
	`, sessionID, agentProvider, canonicalAgent, cwd, source, externalID, mode, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return SessionRecord{}, err
	}
	return s.Session(ctx, sessionID)
}

func (s *Store) EnsureObservedSession(ctx context.Context, sessionID, agent, cwd string) (SessionRecord, error) {
	return s.EnsureObservedSessionWithMode(ctx, sessionID, agent, cwd, "")
}

func (s *Store) EnsureObservedSessionWithMode(ctx context.Context, sessionID, agent, cwd, mode string) (SessionRecord, error) {
	now := time.Now().UTC()
	sessionID = normalizeSessionID(sessionID)
	agentProvider, canonicalAgent := hostedAgentIdentity(agent)
	_, err := s.db.ExecContext(ctx, `
insert into agent_sessions(id, agent_provider, agent, cwd, source, status, mode, created_at, updated_at)
values(?, ?, ?, ?, 'daemon_observed', 'open', ?, ?, ?)
on conflict(id) do update set
  agent_provider = coalesce(nullif(excluded.agent_provider, ''), agent_sessions.agent_provider),
  agent = coalesce(nullif(excluded.agent, ''), agent_sessions.agent),
  cwd = coalesce(nullif(excluded.cwd, ''), agent_sessions.cwd),
  mode = coalesce(nullif(excluded.mode, ''), agent_sessions.mode),
  status = case
    when agent_sessions.source = 'wrapper_owned' then agent_sessions.status
    else 'open'
  end,
  closed_at = case
    when agent_sessions.source = 'wrapper_owned' then agent_sessions.closed_at
    else null
  end,
  updated_at = excluded.updated_at
	`, sessionID, agentProvider, canonicalAgent, cwd, mode, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return SessionRecord{}, err
	}
	return s.Session(ctx, sessionID)
}

func (s *Store) CloseSession(ctx context.Context, sessionID string) error {
	sessionID = normalizeSessionID(sessionID)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
update agent_sessions
set status = 'closed', closed_at = ?, updated_at = ?
where id = ?
	`, now, now, sessionID)
	return err
}

func (s *Store) CloseStaleDaemonObservedSessions(ctx context.Context, olderThan time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
update agent_sessions
set status = 'closed', closed_at = ?, updated_at = ?
where source = 'daemon_observed'
  and status = 'open'
  and updated_at < ?
	`, now, now, olderThan.UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) Session(ctx context.Context, sessionID string) (SessionRecord, error) {
	row := s.db.QueryRowContext(ctx, `
select id, coalesce(agent_provider, ''), coalesce(agent, ''), coalesce(cwd, ''), source, status, coalesce(external_id, ''),
  coalesce(mode, ''), created_at, updated_at, closed_at
from agent_sessions
where id = ?
	`, sessionID)
	return scanSession(row)
}

func (s *Store) SaveDecision(ctx context.Context, event risk.HookEvent, decision risk.RiskDecision) (DecisionRecord, error) {
	now := time.Now().UTC()
	sessionID := normalizeSessionID(event.SessionID)
	event.SessionID = sessionID
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DecisionRecord{}, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	agentProvider, canonicalAgent := hostedAgentIdentity(event.Agent)
	_, err = tx.ExecContext(ctx, `
insert into agent_sessions(id, agent_provider, agent, cwd, source, status, created_at, updated_at)
values(?, ?, ?, ?, 'daemon_observed', 'open', ?, ?)
on conflict(id) do update set
  agent_provider = coalesce(nullif(excluded.agent_provider, ''), agent_sessions.agent_provider),
  agent = coalesce(nullif(excluded.agent, ''), agent_sessions.agent),
  cwd = coalesce(nullif(excluded.cwd, ''), agent_sessions.cwd),
  updated_at = excluded.updated_at
	`, sessionID, agentProvider, canonicalAgent, event.CWD, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return DecisionRecord{}, err
	}

	// Snapshot the mode once so every row of this decision is captured
	// under the same policy, even if the mode flips concurrently.
	captureConfig := s.payloadCaptureConfiguration()

	actionID := "act_" + uuid.NewString()
	if event.HookEventName == "PreToolUse" {
		proposedID := "act_" + uuid.NewString()
		if err := s.insertAction(ctx, tx, proposedID, sessionID, event, decision, canonicalEventRequestProposed, "event", captureConfig, now); err != nil {
			return DecisionRecord{}, err
		}
		// The decided row is the one decision record for this tool call: the
		// Decision Fact overlay writes the engine of record, applied mode,
		// Cedar verdict, provenance, and evidence onto this row. No sibling
		// decision rows (Cedar sidecar, provider dry-run) are written.
		decidedAt := now.Add(time.Millisecond)
		action, err := actionValues(actionID, sessionID, event, decision, canonicalEventRequestDecided, captureConfig, decidedAt)
		if err != nil {
			return DecisionRecord{}, err
		}
		if err := applyDecisionFact(action, event, decision, decidedAt); err != nil {
			return DecisionRecord{}, err
		}
		if err := s.insertActionRecord(ctx, tx, action, "decision", decidedAt); err != nil {
			return DecisionRecord{}, err
		}
	} else {
		if err := s.insertAction(ctx, tx, actionID, sessionID, event, decision, canonicalEventType(event.HookEventName), "outcome", captureConfig, now); err != nil {
			return DecisionRecord{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return DecisionRecord{}, err
	}
	decision.EventID = actionID
	return DecisionRecord{
		ID:            actionID,
		SessionID:     sessionID,
		ToolUseID:     event.ToolUseID,
		HookEventName: event.HookEventName,
		ToolName:      event.ToolName,
		Decision:      decision.Decision,
		ReasonCode:    decision.ReasonCode,
		Reason:        decision.Reason,
		RiskScore:     decision.RiskScore,
		Threshold:     decision.Threshold,
		ModelVersion:  decision.ModelVersion,
		RiskEvent:     decision.RiskEvent,
		CreatedAt:     now,
	}, nil
}

func (s *Store) insertAction(ctx context.Context, tx *sql.Tx, actionID, sessionID string, event risk.HookEvent, decision risk.RiskDecision, canonicalEvent, receiptType string, captureConfig payloadcapture.RuntimeConfiguration, now time.Time) error {
	action, err := actionValues(actionID, sessionID, event, decision, canonicalEvent, captureConfig, now)
	if err != nil {
		return err
	}
	return s.insertActionRecord(ctx, tx, action, receiptType, now)
}

func (s *Store) insertActionRecord(ctx context.Context, tx *sql.Tx, action map[string]any, receiptType string, now time.Time) error {
	// The cursor key orders the hosted export. Stamp it at write time: the
	// event timestamps in the record are captured before this write queues on
	// the store's single serialized connection, and under load a stale stamp
	// can land behind an already-persisted export cursor. Re-stamping here
	// shrinks that stamp-to-commit gap to the instant before COMMIT, well
	// inside the exporter's cursorSafetyLag. This intentionally overwrites any
	// updated_at_cursor_key the caller set in actionValues; `now` is still the
	// business timestamp used for the receipt appended below.
	action["updated_at_cursor_key"] = ledgerTimestampCursorKeyFromTime(time.Now().UTC())
	columns := []string{
		"id", "session_id", "tool_use_id", "canonical_event_type", "adapter_event_name", "correlation_key",
		"tool_name", "provider", "operation", "operation_class", "resource_class", "resource_id", "parameters_redacted_json", "parameters_hash",
		"identity_context_json", "identity_hash", "context_json", "context_hash",
		"policy_id", "policy_version", "policy_hash", "default_posture",
		"decision_result", "decision_category", "adapter_decision", "reason_code", "reason",
		"schema_version", "tool_call_id", "applied_mode", "evaluation_state", "cedar_action", "decision_fact_json",
		"risk_level", "risk_score", "risk_threshold", "model_version", "confidence", "matched_rules_json", "risk_signals_json", "risk_event_json",
		"modifications_json", "approval_context_json", "approval_channel", "approval_request_id", "deferral_context_json",
		"status", "outcome", "output_summary", "output_hash", "error_redacted",
		"tool_input_captured_json", "tool_output_captured_json",
		"proposed_at", "decision_at", "completed_at", "created_at", "updated_at", "updated_at_cursor_key",
	}
	values := []any{
		action["id"], action["session_id"], action["tool_use_id"], action["canonical_event_type"], action["adapter_event_name"], action["correlation_key"],
		action["tool_name"], action["provider"], action["operation"], action["operation_class"], action["resource_class"], action["resource_id"], action["parameters_redacted_json"], action["parameters_hash"],
		action["identity_context_json"], action["identity_hash"], action["context_json"], action["context_hash"],
		action["policy_id"], action["policy_version"], action["policy_hash"], action["default_posture"],
		action["decision_result"], action["decision_category"], action["adapter_decision"], action["reason_code"], action["reason"],
		action["schema_version"], action["tool_call_id"], action["applied_mode"], action["evaluation_state"], action["cedar_action"], action["decision_fact_json"],
		action["risk_level"], action["risk_score"], action["risk_threshold"], action["model_version"], action["confidence"], action["matched_rules_json"], action["risk_signals_json"], action["risk_event_json"],
		action["modifications_json"], action["approval_context_json"], action["approval_channel"], action["approval_request_id"], action["deferral_context_json"],
		action["status"], action["outcome"], action["output_summary"], action["output_hash"], action["error_redacted"],
		action["tool_input_captured_json"], action["tool_output_captured_json"],
		action["proposed_at"], action["decision_at"], action["completed_at"], action["created_at"], action["updated_at"], action["updated_at_cursor_key"],
	}
	placeholders := strings.TrimRight(strings.Repeat("?,", len(columns)), ",")
	if _, err := tx.ExecContext(ctx,
		fmt.Sprintf("insert into authorization_actions(%s) values(%s)", strings.Join(columns, ", "), placeholders),
		values...,
	); err != nil {
		return err
	}
	return s.appendReceipt(ctx, tx, receiptInputFromAction(action, receiptType, now))
}

// capturedInputJSON records tool input once per tool call, on the
// request.proposed row — the decision row correlates via tool_use_id and
// must not duplicate it.
func capturedInputJSON(event risk.HookEvent, canonicalEvent string, mode payloadcapture.Mode) any {
	if canonicalEvent != canonicalEventRequestProposed {
		return nil
	}
	return capturedRecordJSON(event.ToolInput, mode)
}

// capturedOutputJSON records tool output on the observed/failed rows.
func capturedOutputJSON(event risk.HookEvent, canonicalEvent string, mode payloadcapture.Mode) any {
	if canonicalEvent != canonicalEventRequestObserved && canonicalEvent != canonicalEventRequestFailed {
		return nil
	}
	return capturedRecordJSON(event.ToolResponse, mode)
}

func capturedRecordJSON(payload map[string]any, mode payloadcapture.Mode) any {
	record := payloadcapture.Capture(payload, mode)
	if record == nil {
		return nil
	}
	raw, err := record.MarshalJSON()
	if err != nil {
		// Unreachable for records produced by Capture; if it ever happens,
		// surface the failure in the ledger rather than dropping silently —
		// the ledger is this package's log.
		return `{"mode":"capture_failed","reason":"serialization_error"}`
	}
	return string(raw)
}

func actionValues(actionID, sessionID string, event risk.HookEvent, decision risk.RiskDecision, canonicalEvent string, captureConfig payloadcapture.RuntimeConfiguration, now time.Time) (map[string]any, error) {
	riskEvent := decision.RiskEvent
	if canonicalEvent != canonicalEventRequestDecided {
		riskEvent.Decision = ""
		riskEvent.ReasonCode = ""
		riskEvent.DecisionStage = ""
	}
	resourceID, branch := githubResourceScope(event, riskEvent)
	if resourceID != "" {
		riskEvent.Provider = "github"
		riskEvent.ProviderCategory = "source_control"
		if riskEvent.ResourceClass == "" || riskEvent.ResourceClass == "unknown" {
			riskEvent.ResourceClass = "repo"
		}
	}
	riskEventJSON, err := json.Marshal(riskEvent)
	if err != nil {
		return nil, err
	}
	parametersJSON, parametersHash := mustHashJSON(map[string]any{
		"command_summary": riskEvent.CommandSummary,
		"request_summary": riskEvent.RequestSummary,
		"path_class":      riskEvent.PathClass,
	})
	agentProvider, canonicalAgent := hostedAgentIdentity(event.Agent)
	identityPayload := map[string]any{
		"agent": canonicalAgent,
	}
	if agentProvider != "" {
		identityPayload["agent_provider"] = agentProvider
	}
	identityJSON, identityHash := mustHashJSON(identityPayload)
	contextPayload := map[string]any{
		"cwd":             event.CWD,
		"hook_event_name": event.HookEventName,
		"payload_capture": captureConfig,
	}
	if branch != "" {
		contextPayload["github"] = map[string]any{"branch_or_ref": branch}
	}
	contextJSON, contextHash := mustHashJSON(contextPayload)
	policyJSON := map[string]any{
		"policy_version":       riskEvent.PolicyVersion,
		"policy_profile":       riskEvent.PolicyProfile,
		"policy_rule_pack":     riskEvent.PolicyRulePack,
		"policy_rule_id":       riskEvent.PolicyRuleID,
		"policy_rule_category": riskEvent.PolicyRuleCategory,
	}
	_, computedPolicyHash := mustHashJSON(policyJSON)
	if riskEvent.PolicyHash != "" {
		computedPolicyHash = riskEvent.PolicyHash
	}
	matchedRulesJSON := mustJSONText(nonEmptyStrings([]string{riskEvent.PolicyRuleID}))
	riskSignalsJSON := mustJSONText(append([]string{}, riskEvent.Signals...))
	emptyObject := "{}"
	isDecisionEvent := canonicalEvent == canonicalEventRequestDecided
	var decisionResult any
	if isDecisionEvent {
		decisionResult = canonicalDecisionResult(decision.Decision)
	}
	outcome, outputSummary, outputHash, errorRedacted := outcomeValues(event, decision)
	toolInputCaptured := capturedInputJSON(event, canonicalEvent, captureConfig.EffectiveMode)
	toolOutputCaptured := capturedOutputJSON(event, canonicalEvent, captureConfig.EffectiveMode)
	proposedAt := ""
	decisionAt := ""
	completedAt := ""
	switch canonicalEvent {
	case canonicalEventRequestProposed:
		proposedAt = now.Format(time.RFC3339Nano)
	case canonicalEventRequestDecided:
		decisionAt = proposedAt
		if decisionAt == "" {
			decisionAt = now.Format(time.RFC3339Nano)
		}
	case canonicalEventRequestObserved, canonicalEventRequestFailed, canonicalEventSessionEnd:
		completedAt = now.Format(time.RFC3339Nano)
	case canonicalEventSessionStart:
		proposedAt = now.Format(time.RFC3339Nano)
	}
	policyID, policyVersion, actionPolicyHash, decisionCategoryValue, adapterDecisionValue, reasonCode, reasonText := "", "", "", "", "", "", ""
	if isDecisionEvent {
		policyID = riskEvent.PolicyRuleID
		policyVersion = riskEvent.PolicyVersion
		actionPolicyHash = computedPolicyHash
		decisionCategoryValue = decisionCategory(riskEvent)
		adapterDecisionValue = adapterDecision(decision.Decision)
		reasonCode = decision.ReasonCode
		reasonText = decision.Reason
	}
	provider := riskEvent.Provider
	if resourceID != "" {
		provider = "github"
	}

	updatedAt := now.Format(time.RFC3339Nano)

	return map[string]any{
		"id":                        actionID,
		"session_id":                sessionID,
		"tool_use_id":               event.ToolUseID,
		"canonical_event_type":      canonicalEvent,
		"adapter_event_name":        event.HookEventName,
		"correlation_key":           correlationKey(event),
		"tool_name":                 event.ToolName,
		"provider":                  provider,
		"operation":                 riskEvent.Operation,
		"operation_class":           riskEvent.OperationClass,
		"resource_class":            riskEvent.ResourceClass,
		"resource_id":               nullIfEmpty(resourceID),
		"parameters_redacted_json":  parametersJSON,
		"parameters_hash":           parametersHash,
		"identity_context_json":     identityJSON,
		"identity_hash":             identityHash,
		"context_json":              contextJSON,
		"context_hash":              contextHash,
		"policy_id":                 policyID,
		"policy_version":            policyVersion,
		"policy_hash":               actionPolicyHash,
		"default_posture":           "",
		"decision_result":           decisionResult,
		"decision_category":         decisionCategoryValue,
		"adapter_decision":          adapterDecisionValue,
		"reason_code":               reasonCode,
		"reason":                    reasonText,
		"risk_level":                strings.ToUpper(riskEvent.JudgeRiskLevel),
		"risk_score":                nullableFloat(decision.RiskScore),
		"risk_threshold":            nullableFloat(decision.Threshold),
		"model_version":             decision.ModelVersion,
		"confidence":                riskEvent.Confidence,
		"matched_rules_json":        matchedRulesJSON,
		"risk_signals_json":         riskSignalsJSON,
		"risk_event_json":           riskEventJSON,
		"modifications_json":        emptyObject,
		"approval_context_json":     emptyObject,
		"approval_channel":          "",
		"approval_request_id":       "",
		"deferral_context_json":     emptyObject,
		"status":                    actionStatus(canonicalEvent, stringValue(decisionResult)),
		"outcome":                   outcome,
		"output_summary":            outputSummary,
		"output_hash":               outputHash,
		"error_redacted":            errorRedacted,
		"tool_input_captured_json":  toolInputCaptured,
		"tool_output_captured_json": toolOutputCaptured,
		"proposed_at":               nullIfEmpty(proposedAt),
		"decision_at":               nullIfEmpty(decisionAt),
		"completed_at":              nullIfEmpty(completedAt),
		"created_at":                updatedAt,
		"updated_at":                updatedAt,
		"updated_at_cursor_key":     ledgerTimestampCursorKeyFromValues(updatedAt),
	}, nil
}

type receiptInput struct {
	ActionID           string
	SessionID          string
	ReceiptType        string
	DecisionResult     any
	DecisionCategory   string
	ReasonCode         string
	PolicyHash         string
	ContextHash        string
	IdentityHash       string
	RiskEvaluationHash string
	ActionHash         string
	OutcomeHash        string
	Payload            map[string]any
	CreatedAt          time.Time
}

func receiptInputFromAction(action map[string]any, receiptType string, now time.Time) receiptInput {
	riskEventJSON, _ := action["risk_event_json"].(string)
	riskHash := hashString(riskEventJSON)
	decisionResult := stringValue(action["decision_result"])
	actionPayload := map[string]any{
		"id":              action["id"],
		"session_id":      action["session_id"],
		"tool_use_id":     action["tool_use_id"],
		"tool_name":       action["tool_name"],
		"parameters_hash": action["parameters_hash"],
		"context_hash":    action["context_hash"],
		"identity_hash":   action["identity_hash"],
		"policy_hash":     action["policy_hash"],
		"reason_code":     action["reason_code"],
		"risk_hash":       riskHash,
		"outcome_hash":    action["output_hash"],
	}
	if decisionFactJSON := stringValue(action["decision_fact_json"]); decisionFactJSON != "" {
		// The decision fact is the authoritative decision record. Keep its
		// complete canonical JSON inside the signed receipt payload, rather
		// than only mirroring selected columns whose meaning may evolve.
		actionPayload["decision_fact"] = json.RawMessage(decisionFactJSON)
	}
	if decisionResult != "" {
		actionPayload["decision_result"] = decisionResult
	}
	_, actionHash := mustHashJSON(actionPayload)
	payload := map[string]any{
		"receipt_type": receiptType,
		"action":       actionPayload,
		"risk": map[string]any{
			"risk_level": action["risk_level"],
			"risk_score": action["risk_score"],
			"threshold":  action["risk_threshold"],
			"signals":    json.RawMessage(action["risk_signals_json"].(string)),
		},
		"policy": map[string]any{
			"policy_id":      action["policy_id"],
			"policy_version": action["policy_version"],
			"policy_hash":    action["policy_hash"],
			"matched_rules":  json.RawMessage(action["matched_rules_json"].(string)),
		},
		"hashes": map[string]any{
			"context_hash":         action["context_hash"],
			"identity_hash":        action["identity_hash"],
			"risk_evaluation_hash": riskHash,
			"action_hash":          actionHash,
			"outcome_hash":         action["output_hash"],
		},
	}
	if decisionResult != "" {
		payload["decision"] = map[string]any{
			"result":      decisionResult,
			"category":    action["decision_category"],
			"reason_code": action["reason_code"],
			"reason":      action["reason"],
		}
	}
	if receiptType == "outcome" {
		payload["outcome"] = map[string]any{
			"outcome":        action["outcome"],
			"output_summary": action["output_summary"],
			"output_hash":    action["output_hash"],
			"error_redacted": action["error_redacted"],
		}
	}
	return receiptInput{
		ActionID:           action["id"].(string),
		SessionID:          action["session_id"].(string),
		ReceiptType:        receiptType,
		DecisionResult:     nullIfEmpty(decisionResult),
		DecisionCategory:   stringValue(action["decision_category"]),
		ReasonCode:         stringValue(action["reason_code"]),
		PolicyHash:         stringValue(action["policy_hash"]),
		ContextHash:        stringValue(action["context_hash"]),
		IdentityHash:       stringValue(action["identity_hash"]),
		RiskEvaluationHash: riskHash,
		ActionHash:         actionHash,
		OutcomeHash:        stringValue(action["output_hash"]),
		Payload:            payload,
		CreatedAt:          now,
	}
}

func receiptActionValues(ctx context.Context, tx *sql.Tx, actionID string) (map[string]any, error) {
	var (
		id, sessionID, toolUseID, toolName                    string
		parametersHash, contextHash, identityHash, policyHash string
		reasonCode, riskEventJSON, outputHash                 string
		decisionCategory, reason, riskLevel, riskSignalsJSON  string
		policyID, policyVersion, matchedRulesJSON             string
		outcome, outputSummary, errorRedacted                 string
		decisionFactJSON                                      string
		decisionResult                                        sql.NullString
		riskScore, riskThreshold                              sql.NullFloat64
	)
	err := tx.QueryRowContext(ctx, `
select id, session_id, coalesce(tool_use_id, ''), coalesce(tool_name, ''),
  coalesce(parameters_hash, ''), coalesce(context_hash, ''), coalesce(identity_hash, ''),
  coalesce(policy_hash, ''), decision_result, coalesce(reason_code, ''),
  coalesce(risk_event_json, '{}'), coalesce(output_hash, ''),
  coalesce(decision_category, ''), coalesce(reason, ''), coalesce(risk_level, ''),
  risk_score, risk_threshold, coalesce(risk_signals_json, '[]'),
  coalesce(policy_id, ''), coalesce(policy_version, ''), coalesce(matched_rules_json, '[]'),
  coalesce(outcome, ''), coalesce(output_summary, ''), coalesce(error_redacted, ''),
  coalesce(decision_fact_json, '')
from authorization_actions
where id = ?
	`, actionID).Scan(
		&id, &sessionID, &toolUseID, &toolName,
		&parametersHash, &contextHash, &identityHash, &policyHash,
		&decisionResult, &reasonCode, &riskEventJSON, &outputHash,
		&decisionCategory, &reason, &riskLevel, &riskScore, &riskThreshold,
		&riskSignalsJSON, &policyID, &policyVersion, &matchedRulesJSON,
		&outcome, &outputSummary, &errorRedacted, &decisionFactJSON,
	)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":                 id,
		"session_id":         sessionID,
		"tool_use_id":        toolUseID,
		"tool_name":          toolName,
		"parameters_hash":    parametersHash,
		"context_hash":       contextHash,
		"identity_hash":      identityHash,
		"policy_hash":        policyHash,
		"decision_result":    nullableSQLString(decisionResult),
		"reason_code":        reasonCode,
		"risk_event_json":    riskEventJSON,
		"output_hash":        outputHash,
		"decision_category":  decisionCategory,
		"reason":             reason,
		"risk_level":         riskLevel,
		"risk_score":         nullableSQLFloat(riskScore),
		"risk_threshold":     nullableSQLFloat(riskThreshold),
		"risk_signals_json":  riskSignalsJSON,
		"policy_id":          policyID,
		"policy_version":     policyVersion,
		"matched_rules_json": matchedRulesJSON,
		"outcome":            outcome,
		"output_summary":     outputSummary,
		"error_redacted":     errorRedacted,
		"decision_fact_json": decisionFactJSON,
	}, nil
}

func (s *Store) appendReceipt(ctx context.Context, tx *sql.Tx, input receiptInput) error {
	previousHash, err := previousReceiptHash(ctx, tx)
	if err != nil {
		return err
	}
	payload := copyMap(input.Payload)
	payload["previous_receipt_hash"] = previousHash
	receiptPayloadJSON, err := jsonText(payload)
	if err != nil {
		return err
	}
	receiptHash := hashString(receiptPayloadJSON)
	signatureAlgorithm := "none"
	signature := ""
	keyID := ""
	if s.signer != nil {
		signature, signatureAlgorithm, keyID, err = s.signer.Sign([]byte(receiptHash))
		if err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `
insert into authorization_receipts(
  id, action_id, session_id, receipt_type,
  decision_result, decision_category, reason_code,
  policy_hash, context_hash, identity_hash, risk_evaluation_hash, action_hash, outcome_hash,
  receipt_payload_json, previous_receipt_hash, receipt_hash, signature, signature_algorithm, key_id,
  created_at
) values(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, "rcpt_"+uuid.NewString(), input.ActionID, input.SessionID, input.ReceiptType,
		input.DecisionResult, input.DecisionCategory, input.ReasonCode,
		input.PolicyHash, input.ContextHash, input.IdentityHash, input.RiskEvaluationHash, input.ActionHash, input.OutcomeHash,
		receiptPayloadJSON, previousHash, receiptHash, signature, signatureAlgorithm, keyID,
		input.CreatedAt.Format(time.RFC3339Nano))
	return err
}

func previousReceiptHash(ctx context.Context, tx *sql.Tx) (string, error) {
	var previous string
	err := tx.QueryRowContext(ctx, `
select receipt_hash
from authorization_receipts
order by rowid desc
limit 1
	`).Scan(&previous)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return previous, err
}

const (
	canonicalEventRequestProposed = "request.proposed"
	canonicalEventRequestDecided  = "request.decided"
	canonicalEventRequestObserved = "request.observed"
	canonicalEventRequestFailed   = "request.failed"
	canonicalEventSessionStart    = "session.start"
	canonicalEventSessionEnd      = "session.end"
)

func canonicalEventType(hookEventName string) string {
	switch hookEventName {
	case "SessionStart":
		return canonicalEventSessionStart
	case "SessionEnd":
		return canonicalEventSessionEnd
	case "PostToolUse":
		return canonicalEventRequestObserved
	case "PostToolUseFailure":
		return canonicalEventRequestFailed
	default:
		return canonicalEventRequestObserved
	}
}

func canonicalDecisionResult(decision risk.Decision) string {
	switch strings.ToLower(strings.TrimSpace(string(decision))) {
	case "allow":
		return "allow"
	case "deny":
		fallthrough
	default:
		return "deny"
	}
}

func actionStatus(canonicalEvent, decisionResult string) string {
	switch canonicalEvent {
	case canonicalEventRequestProposed:
		return "proposed"
	case canonicalEventRequestObserved:
		return "completed"
	case canonicalEventRequestFailed:
		return "failed"
	case canonicalEventSessionStart:
		return "started"
	case canonicalEventSessionEnd:
		return "completed"
	}
	switch decisionResult {
	case "allow":
		return "authorized"
	default:
		return "blocked"
	}
}

func adapterDecision(decision risk.Decision) string {
	normalized := strings.ToLower(strings.TrimSpace(string(decision)))
	switch normalized {
	case "allow", "deny":
		return normalized
	}
	if normalized == "" {
		normalized = "empty"
	}
	normalized = strings.NewReplacer(" ", "_", "-", "_").Replace(normalized)
	return "unsupported_" + normalized + "_fail_closed"
}

func outcomeValues(event risk.HookEvent, decision risk.RiskDecision) (outcome, summary, outputHash, errorRedacted string) {
	switch event.HookEventName {
	case "PostToolUse":
		outcome = "success"
	case "PostToolUseFailure":
		outcome = "error"
		errorRedacted = decision.Reason
	default:
		outcome = "not_executed"
	}
	summary = decision.RiskEvent.RequestSummary
	if summary == "" {
		summary = decision.RiskEvent.CommandSummary
	}
	if len(event.ToolResponse) > 0 {
		_, outputHash = mustHashJSON(event.ToolResponse)
	}
	return outcome, summary, outputHash, errorRedacted
}

func decisionCategory(event risk.RiskEvent) string {
	if event.PolicyRuleCategory != "" {
		return event.PolicyRuleCategory
	}
	if event.DecisionStage != "" {
		return event.DecisionStage
	}
	if event.ReasonCode != "" {
		return event.ReasonCode
	}
	return "default"
}

func correlationKey(event risk.HookEvent) string {
	if event.ToolUseID != "" {
		return event.SessionID + ":" + event.ToolUseID
	}
	return event.SessionID + ":" + event.HookEventName + ":" + event.ToolName
}

var (
	githubRemoteRE = regexp.MustCompile(`(?i)(?:github\.com[:/])([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$`)
	githubURLRE    = regexp.MustCompile(`(?i)github\.com[:/]([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:\.git)?(?:[/\s'"<>]|$)`)
	githubRepoRE   = regexp.MustCompile(`\b([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\b`)
)

func githubResourceScope(event risk.HookEvent, riskEvent risk.RiskEvent) (resourceID, branch string) {
	command := commandFromHookInput(event.ToolInput)
	if riskEvent.Provider != "github" && riskEvent.Provider != "git" && !strings.Contains(strings.ToLower(command), "github.com") {
		return "", ""
	}
	if repo := githubRepoFromCommand(command); repo != "" {
		return repo, currentGitBranch(event.CWD)
	}
	if repo := githubRepoFromCWD(event.CWD); repo != "" {
		return repo, currentGitBranch(event.CWD)
	}
	return "", ""
}

func githubRepoFromCommand(command string) string {
	lowerCommand := strings.ToLower(command)
	if !strings.Contains(lowerCommand, "gh ") && !strings.Contains(lowerCommand, "github.com") {
		return ""
	}
	if strings.Contains(lowerCommand, "github.com") {
		match := githubURLRE.FindStringSubmatch(command)
		if len(match) >= 2 {
			return strings.TrimSuffix(match[1], ".git")
		}
	}
	match := githubRepoRE.FindStringSubmatch(command)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSuffix(match[1], ".git")
}

func githubRepoFromCWD(cwd string) string {
	if strings.TrimSpace(cwd) == "" {
		return ""
	}
	remote := gitOutput(cwd, "remote", "get-url", "origin")
	if remote == "" {
		return ""
	}
	match := githubRemoteRE.FindStringSubmatch(remote)
	if len(match) < 2 {
		return ""
	}
	return strings.TrimSuffix(match[1], ".git")
}

func currentGitBranch(cwd string) string {
	if strings.TrimSpace(cwd) == "" {
		return ""
	}
	branch := gitOutput(cwd, "rev-parse", "--abbrev-ref", "HEAD")
	if branch == "HEAD" {
		return ""
	}
	return branch
}

func gitOutput(cwd string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", cwd}, args...)...)
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func commandFromHookInput(input map[string]any) string {
	for _, key := range []string{"command", "cmd", "script"} {
		if value, ok := input[key].(string); ok {
			return value
		}
	}
	return ""
}

func mustHashJSON(value any) (string, string) {
	payload, hash, err := hashJSON(value)
	if err != nil {
		return "{}", hashString("{}")
	}
	return payload, hash
}

func mustJSONText(value any) string {
	payload, err := jsonText(value)
	if err != nil {
		return "[]"
	}
	return payload
}

func nonEmptyStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func nullableSQLFloat(value sql.NullFloat64) any {
	if !value.Valid {
		return nil
	}
	return value.Float64
}

func nullableSQLString(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func copyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

// Summary counts each tool call once. New writes produce exactly one
// decision row per call (the Decision Fact overlay), so no filtering is
// needed for them; the dry_run exclusion below survives only as bounded
// tolerance for rows written by pre-fact versions of this store.
func (s *Store) Summary(ctx context.Context) (Summary, error) {
	var summary Summary
	row := s.db.QueryRowContext(ctx, `
select
	  coalesce(sum(critical), 0),
	  0,
	  coalesce(sum(actions), 0),
	  (select count(*) from agent_sessions)
	from (
	  select case when decision_result = 'deny' then 1 else 0 end as critical, 1 as actions
	  from authorization_actions
	  where canonical_event_type <> 'request.proposed'
	    and coalesce(decision_category, '') <> 'dry_run'
	)
	`)
	if err := row.Scan(&summary.Critical, &summary.Warnings, &summary.Actions, &summary.Sessions); err != nil {
		return Summary{}, err
	}
	return summary, nil
}

func (s *Store) Sessions(ctx context.Context) ([]SessionSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
select actions.session_id,
	  sum(critical) as critical,
	  0 as warnings,
	  count(*) as actions,
	  max(latest_at) as latest_at,
	  coalesce(agent_sessions.mode, '') as mode,
	  coalesce(agent_sessions.status, '') as status,
	  coalesce(agent_sessions.created_at, max(latest_at)) as created_at,
	  coalesce(agent_sessions.updated_at, max(latest_at)) as updated_at,
	  agent_sessions.closed_at
	from (
	  select session_id, case when decision_result = 'deny' then 1 else 0 end as critical, updated_at as latest_at
	  from authorization_actions
	  where canonical_event_type <> 'request.proposed'
	    and coalesce(decision_category, '') <> 'dry_run'
		) actions
left join agent_sessions on agent_sessions.id = actions.session_id
group by actions.session_id, agent_sessions.mode, agent_sessions.status, agent_sessions.created_at, agent_sessions.updated_at, agent_sessions.closed_at
order by latest_at desc
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := []SessionSummary{}
	for rows.Next() {
		var item SessionSummary
		var latest, created, updated string
		var closed sql.NullString
		if err := rows.Scan(&item.SessionID, &item.Critical, &item.Warnings, &item.Actions, &latest, &item.Mode, &item.Status, &created, &updated, &closed); err != nil {
			return nil, err
		}
		if err := parseSessionSummaryTimes(&item, latest, created, updated, closed); err != nil {
			return nil, err
		}
		sessions = append(sessions, item)
	}
	return sessions, rows.Err()
}

func (s *Store) SessionSummary(ctx context.Context, sessionID string) (SessionSummary, error) {
	var item SessionSummary
	var latest, created, updated string
	var closed sql.NullString
	row := s.db.QueryRowContext(ctx, `
select actions.session_id,
	  sum(critical),
	  0,
	  count(*),
	  max(latest_at),
	  coalesce(agent_sessions.mode, ''),
	  coalesce(agent_sessions.status, ''),
	  coalesce(agent_sessions.created_at, max(latest_at)),
	  coalesce(agent_sessions.updated_at, max(latest_at)),
	  agent_sessions.closed_at
	from (
	  select session_id, case when decision_result = 'deny' then 1 else 0 end as critical, updated_at as latest_at
	  from authorization_actions
	  where session_id = ? and canonical_event_type <> 'request.proposed'
	    and coalesce(decision_category, '') <> 'dry_run'
		) actions
left join agent_sessions on agent_sessions.id = actions.session_id
group by actions.session_id, agent_sessions.mode, agent_sessions.status, agent_sessions.created_at, agent_sessions.updated_at, agent_sessions.closed_at
	`, sessionID)
	if err := row.Scan(&item.SessionID, &item.Critical, &item.Warnings, &item.Actions, &latest, &item.Mode, &item.Status, &created, &updated, &closed); err != nil {
		return SessionSummary{}, err
	}
	if err := parseSessionSummaryTimes(&item, latest, created, updated, closed); err != nil {
		return SessionSummary{}, err
	}
	return item, nil
}

func (s *Store) Events(ctx context.Context, sessionID string) ([]DecisionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
select id, session_id, coalesce(tool_use_id, ''), hook_event_name, coalesce(tool_name, ''),
	  decision, reason_code, reason, risk_score, threshold, coalesce(model_version, ''),
	  risk_event_json, created_at
	from (
	  select id, session_id, tool_use_id, coalesce(adapter_event_name, '') as hook_event_name, tool_name,
	    coalesce(decision_result, '') as decision,
	    coalesce(reason_code, '') as reason_code, coalesce(reason, '') as reason, risk_score, risk_threshold as threshold, model_version, risk_event_json, updated_at as created_at
	  from authorization_actions
	  where canonical_event_type = 'request.decided'
	    and coalesce(decision_category, '') <> 'dry_run'
		)
	where session_id = ?
order by created_at desc
	`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []DecisionRecord{}
	for rows.Next() {
		record, err := scanDecision(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func scanDecision(scanner interface{ Scan(...any) error }) (DecisionRecord, error) {
	var record DecisionRecord
	var score sql.NullFloat64
	var threshold sql.NullFloat64
	var riskEventJSON string
	var created string
	if err := scanner.Scan(&record.ID, &record.SessionID, &record.ToolUseID, &record.HookEventName, &record.ToolName,
		&record.Decision, &record.ReasonCode, &record.Reason, &score, &threshold, &record.ModelVersion,
		&riskEventJSON, &created); err != nil {
		return DecisionRecord{}, err
	}
	if score.Valid {
		record.RiskScore = &score.Float64
	}
	if threshold.Valid {
		record.Threshold = &threshold.Float64
	}
	if err := json.Unmarshal([]byte(riskEventJSON), &record.RiskEvent); err != nil {
		return DecisionRecord{}, err
	}
	createdAt, err := parseStoredTime("decision created_at", created)
	if err != nil {
		return DecisionRecord{}, err
	}
	record.CreatedAt = createdAt
	return record, nil
}

func scanSession(scanner interface{ Scan(...any) error }) (SessionRecord, error) {
	var record SessionRecord
	var created, updated string
	var closed sql.NullString
	if err := scanner.Scan(
		&record.ID,
		&record.AgentProvider,
		&record.Agent,
		&record.CWD,
		&record.Source,
		&record.Status,
		&record.ExternalID,
		&record.Mode,
		&created,
		&updated,
		&closed,
	); err != nil {
		return SessionRecord{}, err
	}
	createdAt, err := parseStoredTime("session created_at", created)
	if err != nil {
		return SessionRecord{}, err
	}
	updatedAt, err := parseStoredTime("session updated_at", updated)
	if err != nil {
		return SessionRecord{}, err
	}
	record.CreatedAt = createdAt
	record.UpdatedAt = updatedAt
	if closed.Valid && closed.String != "" {
		closedAt, err := parseStoredTime("session closed_at", closed.String)
		if err != nil {
			return SessionRecord{}, err
		}
		record.ClosedAt = &closedAt
	}
	return record, nil
}

func hostedAgentIdentity(agent string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(agent)) {
	case "claude", "claude-code", "claude_code":
		return "anthropic", "claude_code"
	case "cowork", "claude-cowork", "claude_cowork":
		return "anthropic", "claude_cowork"
	default:
		return "", strings.TrimSpace(agent)
	}
}

func parseSessionSummaryTimes(item *SessionSummary, latest, created, updated string, closed sql.NullString) error {
	latestAt, err := parseStoredTime("session latest_at", latest)
	if err != nil {
		return err
	}
	createdAt, err := parseStoredTime("session created_at", created)
	if err != nil {
		return err
	}
	updatedAt, err := parseStoredTime("session updated_at", updated)
	if err != nil {
		return err
	}
	item.LatestAt = latestAt
	item.CreatedAt = createdAt
	item.UpdatedAt = updatedAt
	if closed.Valid && closed.String != "" {
		closedAt, err := parseStoredTime("session closed_at", closed.String)
		if err != nil {
			return err
		}
		item.ClosedAt = &closedAt
	}
	return nil
}

func parseStoredTime(label, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s %q: %w", label, value, err)
	}
	return parsed, nil
}

func nullableFloat(value *float64) any {
	if value == nil {
		return nil
	}
	return *value
}

func normalizeSessionID(sessionID string) string {
	if sessionID == "" {
		return "local"
	}
	return sessionID
}
