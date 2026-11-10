package sqlite

import (
	"context"
	"fmt"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/payloadcapture"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRecoveryAcrossHistoricalSourcesE2E(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.SetHistoricalTurnRecovery(true)
	s.SetPayloadCaptureConfiguration(payloadcapture.RuntimeConfiguration{ConfiguredMode: payloadcapture.ModeFull, EffectiveMode: payloadcapture.ModeFull, Confirmed: true, ConfigIdentity: "review-fixture", WorkTypeClassification: true})
	if _, err := s.EnsureObservedSessionWithMode(ctx, "parent", "claude", dir, "observe"); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-9 * 24 * time.Hour)
	parent := filepath.Join(dir, "parent.jsonl")
	// A real final prompt without a newline, and no parent usage yet.
	if err := os.WriteFile(parent, []byte(fmt.Sprintf(`{"type":"user","sessionId":"parent","timestamp":%q,"message":{"content":"Build the background report"}}`, base.Format(time.RFC3339Nano))), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.TrackToolTranscript(ctx, hook.Event{SessionID: "parent", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: parent}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`update tool_usage_sources set last_seen=?`, base.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "child.jsonl")
	data := fmt.Sprintf(`{"type":"assistant","isSidechain":true,"sessionId":"parent","timestamp":%q,"message":{"id":"child-request","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Read"}],"usage":{"input_tokens":10,"output_tokens":5}}}`, base.Add(time.Minute).Format(time.RFC3339Nano)) + "\n"
	if err := os.WriteFile(child, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.TrackToolTranscript(ctx, hook.Event{SessionID: "parent", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: child}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	records, err := s.PendingToolUsage(ctx, 10)
	if err != nil || len(records) != 1 || records[0].TurnID == "" {
		t.Fatalf("parent-only unterminated prompt not recovered for background usage: %+v %v", records, err)
	}
	// Reproduce a transient recovery failure outside the seven-day window.
	if _, err := s.db.Exec(`delete from turns`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`update tool_usage_records set payload=json_remove(payload,'$.turn_id'),exported=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`update tool_usage_sources set last_seen=?,turn_recovery_version=-1,fingerprint='restamp:'||fingerprint where transcript_path=?`, base.Format(time.RFC3339Nano), child); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	records, err = s.PendingToolUsage(ctx, 10)
	if err != nil || len(records) != 1 || records[0].TurnID == "" {
		t.Fatalf("historical pending recovery was not retried: %+v %v", records, err)
	}
}
