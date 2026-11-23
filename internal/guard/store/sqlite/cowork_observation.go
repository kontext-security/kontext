package sqlite

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/kontext-security/kontext/internal/guard/risk"
)

// SaveCoworkTranscriptObservation records retrospective evidence, never an
// authorization decision or a claim that a Claude hook fired. Callers validate
// the session-side collector's bounded message before entering the store.
func (s *Store) SaveCoworkTranscriptObservation(ctx context.Context, session, toolID, command string, failed bool, observedAt time.Time) (string, error) {
	id := "act_" + uuid.NewSHA1(uuid.NameSpaceURL, []byte("cowork.vm_mounted_transcript:"+session+":"+toolID)).String()
	now := time.Now().UTC()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var present int
	if err := tx.QueryRowContext(ctx, `select count(*) from authorization_actions where id=?`, id).Scan(&present); err != nil {
		return "", err
	}
	if present != 0 {
		return id, nil
	}
	provider, agent := hostedAgentIdentity("cowork")
	_, err = tx.ExecContext(ctx, `insert into agent_sessions(id,agent_provider,agent,source,status,mode,created_at,updated_at)
values(?,?,?,'daemon_observed','open','observe',?,?) on conflict(id) do update set updated_at=excluded.updated_at`, session, provider, agent, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		return "", err
	}
	event := risk.HookEvent{SessionID: session, Agent: "cowork", HookEventName: "CoworkTranscriptToolResult", ToolName: "Bash", ToolUseID: toolID, ToolInput: map[string]any{"command": command}}
	canonical, outcome := canonicalEventRequestObserved, "success"
	if failed {
		canonical, outcome = canonicalEventRequestFailed, "error"
	}
	action, err := actionValues(id, session, event, risk.RiskDecision{RiskEvent: risk.NormalizeHookEvent(event)}, canonical, s.payloadCaptureConfiguration(), now)
	if err != nil {
		return "", err
	}
	var evidence map[string]any
	if err := json.Unmarshal([]byte(stringValue(action["context_json"])), &evidence); err != nil {
		return "", err
	}
	evidence["capture_source"] = "cowork.vm_mounted_transcript"
	evidence["original_tool_name"] = "mcp__workspace__bash"
	evidence["source_timestamp"] = observedAt.UTC().Format(time.RFC3339Nano)
	evidence["native_hook"] = false
	contextJSON, contextHash := mustHashJSON(evidence)
	action["context_json"], action["context_hash"] = contextJSON, contextHash
	action["outcome"] = outcome
	// Only the normalizer's redacted summaries are retained. Neither transcript
	// text, raw command payload, output, prompt nor thinking is persisted here.
	action["tool_input_captured_json"], action["tool_output_captured_json"] = nil, nil
	if err := s.insertActionRecord(ctx, tx, action, "outcome", now); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return id, nil
}
