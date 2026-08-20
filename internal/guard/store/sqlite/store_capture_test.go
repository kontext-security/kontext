package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func saveCaptureFixtureDecision(t *testing.T, store *Store, hookEvent string, toolInput, toolResponse map[string]any) {
	t.Helper()
	_, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s-capture",
		Agent:         "claude-code",
		HookEventName: hookEvent,
		ToolName:      "Bash",
		ToolUseID:     "tool-capture-1",
		CWD:           "/tmp/project",
		ToolInput:     toolInput,
		ToolResponse:  toolResponse,
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "normal command",
		ReasonCode: "normal_tool_call",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func capturedColumn(t *testing.T, store *Store, canonicalEvent, column string) sql.NullString {
	t.Helper()
	var value sql.NullString
	err := store.db.QueryRowContext(context.Background(),
		"select "+column+" from authorization_actions where canonical_event_type = ?",
		canonicalEvent,
	).Scan(&value)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func setPayloadCaptureModeForTest(store *Store, mode payloadcapture.Mode) {
	store.SetPayloadCaptureConfiguration(payloadcapture.RuntimeConfiguration{
		ConfiguredMode: mode,
		EffectiveMode:  mode,
		ConfigIdentity: strings.Repeat("f", 64),
		Confirmed:      true,
	})
}

func TestSaveDecisionCapturesPayloadsInFullMode(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	setPayloadCaptureModeForTest(store, payloadcapture.ModeFull)

	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{
		"command": "GITHUB_TOKEN=super-secret-raw-value gh api /user",
	}, nil)
	saveCaptureFixtureDecision(t, store, "PostToolUse", map[string]any{
		"command": "GITHUB_TOKEN=super-secret-raw-value gh api /user",
	}, map[string]any{
		"content": "api_key=another-raw-secret ok",
	})

	// Input is recorded once, on the proposed row only.
	proposedInput := capturedColumn(t, store, "request.proposed", "tool_input_captured_json")
	if !proposedInput.Valid {
		t.Fatal("proposed row is missing the captured tool input")
	}
	var inputRecord map[string]any
	if err := json.Unmarshal([]byte(proposedInput.String), &inputRecord); err != nil {
		t.Fatal(err)
	}
	if inputRecord["mode"] != "full" || inputRecord["redacted"] != true {
		t.Fatalf("unexpected input record: %v", inputRecord)
	}
	if strings.Contains(proposedInput.String, "super-secret-raw-value") {
		t.Fatal("raw secret survived into the stored input record")
	}
	if decidedInput := capturedColumn(t, store, "request.decided", "tool_input_captured_json"); decidedInput.Valid {
		t.Fatal("decision row must not duplicate the captured input")
	}

	// Output is recorded on the observed row.
	observedOutput := capturedColumn(t, store, "request.observed", "tool_output_captured_json")
	if !observedOutput.Valid {
		t.Fatal("observed row is missing the captured tool output")
	}
	if strings.Contains(observedOutput.String, "another-raw-secret") {
		t.Fatal("raw secret survived into the stored output record")
	}
	if observedInput := capturedColumn(t, store, "request.observed", "tool_input_captured_json"); observedInput.Valid {
		t.Fatal("observed row must not carry captured input")
	}
}

func TestSaveDecisionDefaultModeWritesNoCapturedPayloads(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// No capture configuration: the default must be byte-identical to
	// the pre-capture behavior.

	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{
		"command": "git status",
	}, nil)
	saveCaptureFixtureDecision(t, store, "PostToolUse", map[string]any{
		"command": "git status",
	}, map[string]any{
		"content": "clean working tree",
	})

	for _, canonicalEvent := range []string{"request.proposed", "request.decided", "request.observed"} {
		for _, column := range []string{"tool_input_captured_json", "tool_output_captured_json"} {
			if value := capturedColumn(t, store, canonicalEvent, column); value.Valid {
				t.Fatalf("%s.%s = %q, want NULL in default mode", canonicalEvent, column, value.String)
			}
		}
	}
}

func TestLedgerExportOmitsEmptyCapturedPayloadFields(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{
		"command": "git status",
	}, nil)

	records, err := store.AuthorizationActions(context.Background(), LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) == 0 {
		t.Fatal("expected exported action records")
	}
	for _, record := range records {
		for _, key := range []string{"tool_input_captured_json", "tool_output_captured_json"} {
			if _, present := record[key]; present {
				t.Fatalf("record %v mentions %s; empty captured fields must stay off the wire", record["id"], key)
			}
		}
	}
}

func TestLedgerExportDecodesCapturedPayloadRecords(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	setPayloadCaptureModeForTest(store, payloadcapture.ModeFull)

	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{
		"command": "curl https://example.test",
	}, nil)

	records, err := store.AuthorizationActions(context.Background(), LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var captured map[string]any
	for _, record := range records {
		if record["canonical_event_type"] != "request.proposed" {
			continue
		}
		decoded, ok := record["tool_input_captured_json"].(map[string]any)
		if !ok {
			t.Fatalf("captured input is %T, want decoded object", record["tool_input_captured_json"])
		}
		captured = decoded
	}
	if captured == nil {
		t.Fatal("no proposed record with captured input exported")
	}
	if captured["mode"] != "full" {
		t.Fatalf("captured mode = %v", captured["mode"])
	}
	if _, hasValue := captured["value"]; !hasValue {
		t.Fatal("captured record is missing its value")
	}
}

func TestMigrationAddsCapturedPayloadColumns(t *testing.T) {
	path := t.TempDir() + "/guard.db"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(context.Background(), `
create table authorization_actions (
  id text primary key,
  session_id text not null,
  canonical_event_type text not null,
  decision_result text,
  status text not null,
  created_at text not null,
  updated_at text not null
);
insert into authorization_actions (
  id, session_id, canonical_event_type, decision_result, status, created_at, updated_at
) values (
  'act_precapture', 's1', 'request.decided', 'allow', 'authorized',
  '2026-05-26T10:00:00Z', '2026-05-26T10:00:00Z'
);
`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, column := range []string{"tool_input_captured_json", "tool_output_captured_json"} {
		var count int
		err := store.db.QueryRowContext(context.Background(), `
select count(*) from pragma_table_info('authorization_actions') where name = ?
		`, column).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("column %s missing after migration", column)
		}
	}

	if value := capturedColumn(t, store, "request.decided", "tool_input_captured_json"); value.Valid {
		t.Fatalf("pre-capture row gained a value: %q", value.String)
	}
}

// capturedRecordJSON falls back to a hardcoded capture_failed literal when
// MarshalJSON fails — a path unreachable for records produced by Capture, so
// it cannot be exercised end-to-end. Pin the literal to the wire format the
// package actually emits so the two cannot drift apart silently.
func TestCaptureFailedFallbackLiteralMatchesWireFormat(t *testing.T) {
	canonical, err := payloadcapture.Payload{
		Mode:   "capture_failed",
		Reason: payloadcapture.ReasonSerializationError,
	}.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal canonical capture_failed record: %v", err)
	}
	const fallback = `{"mode":"capture_failed","reason":"serialization_error"}`
	if string(canonical) != fallback {
		t.Fatalf("fallback literal diverged from wire format:\nliteral: %s\nwire:    %s", fallback, canonical)
	}
}

// The managed daemon applies a complete capture configuration whenever the
// endpoint snapshot refreshes. The store must read the CURRENT configuration
// per recorded event — no restart, no per-session pinning.
func TestSaveDecisionModeChangeAppliesToNextEvent(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	capturedProposedRows := func() int {
		t.Helper()
		var count int
		err := store.db.QueryRowContext(context.Background(),
			"select count(*) from authorization_actions where canonical_event_type = 'request.proposed' and tool_input_captured_json is not null",
		).Scan(&count)
		if err != nil {
			t.Fatal(err)
		}
		return count
	}

	// Default (summary): nothing captured.
	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{"command": "git status"}, nil)
	if got := capturedProposedRows(); got != 0 {
		t.Fatalf("captured rows before mode flip = %d, want 0", got)
	}

	// Snapshot flips to full: the very next event captures.
	setPayloadCaptureModeForTest(store, payloadcapture.ModeFull)
	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{"command": "git diff"}, nil)
	if got := capturedProposedRows(); got != 1 {
		t.Fatalf("captured rows after flip to full = %d, want 1", got)
	}

	// Snapshot flips back to summary: capture stops again.
	setPayloadCaptureModeForTest(store, payloadcapture.ModeSummary)
	saveCaptureFixtureDecision(t, store, "PreToolUse", map[string]any{"command": "git log"}, nil)
	if got := capturedProposedRows(); got != 1 {
		t.Fatalf("captured rows after flip back to summary = %d, want 1", got)
	}
}

func TestSaveDecisionSnapshotsConcurrentCaptureConfiguration(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	full := payloadcapture.RuntimeConfiguration{
		ConfiguredMode: payloadcapture.ModeFull,
		EffectiveMode:  payloadcapture.ModeFull,
		ConfigIdentity: strings.Repeat("a", 64),
		Confirmed:      true,
	}
	summary := payloadcapture.RuntimeConfiguration{
		ConfiguredMode: payloadcapture.ModeSummary,
		EffectiveMode:  payloadcapture.ModeSummary,
		ConfigIdentity: strings.Repeat("b", 64),
		Confirmed:      true,
	}
	store.SetPayloadCaptureConfiguration(summary)
	stop := make(chan struct{})
	var flips sync.WaitGroup
	flips.Add(1)
	go func() {
		defer flips.Done()
		for {
			select {
			case <-stop:
				return
			default:
				store.SetPayloadCaptureConfiguration(full)
				store.SetPayloadCaptureConfiguration(summary)
			}
		}
	}()
	for index := range 40 {
		_, err := store.SaveDecision(context.Background(), risk.HookEvent{
			SessionID:     "s-capture-concurrent",
			Agent:         "claude-code",
			HookEventName: "PreToolUse",
			ToolName:      "Bash",
			ToolUseID:     fmt.Sprintf("tool-flip-%02d", index),
			CWD:           "/tmp/project",
			ToolInput:     map[string]any{"command": "git status"},
		}, risk.RiskDecision{Decision: risk.DecisionAllow, Reason: "test", ReasonCode: "test"})
		if err != nil {
			close(stop)
			flips.Wait()
			t.Fatal(err)
		}
	}
	close(stop)
	flips.Wait()

	rows, err := store.db.QueryContext(context.Background(), `
select tool_use_id, canonical_event_type, context_json, tool_input_captured_json
from authorization_actions
where session_id = 's-capture-concurrent'
order by tool_use_id, case canonical_event_type when 'request.proposed' then 0 else 1 end`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type observed struct {
		config   payloadcapture.RuntimeConfiguration
		proposed bool
	}
	byToolUse := map[string]observed{}
	for rows.Next() {
		var toolUseID, eventType, contextJSON string
		var captured sql.NullString
		if err := rows.Scan(&toolUseID, &eventType, &contextJSON, &captured); err != nil {
			t.Fatal(err)
		}
		var contextValue struct {
			PayloadCapture payloadcapture.RuntimeConfiguration `json:"payload_capture"`
		}
		if err := json.Unmarshal([]byte(contextJSON), &contextValue); err != nil {
			t.Fatal(err)
		}
		config := contextValue.PayloadCapture
		if !config.Confirmed || config.ConfiguredMode != config.EffectiveMode ||
			(config.ConfigIdentity != full.ConfigIdentity && config.ConfigIdentity != summary.ConfigIdentity) {
			t.Fatalf("invalid capture evidence for %s: %#v", toolUseID, config)
		}
		if eventType == canonicalEventRequestProposed {
			if captured.Valid != (config.EffectiveMode == payloadcapture.ModeFull) {
				t.Fatalf("capture/evidence mismatch for %s: config=%#v captured=%t", toolUseID, config, captured.Valid)
			}
			byToolUse[toolUseID] = observed{config: config, proposed: true}
			continue
		}
		proposed := byToolUse[toolUseID]
		if !proposed.proposed || proposed.config != config {
			t.Fatalf("decision %s mixed capture snapshots: proposed=%#v decided=%#v", toolUseID, proposed.config, config)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(byToolUse) != 40 {
		t.Fatalf("observed decisions = %d, want 40", len(byToolUse))
	}
}
