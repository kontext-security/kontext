package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hook"

	"github.com/kontext-security/kontext/internal/payloadcapture"
)

// A prompt opt-out kept through a rollback records the prompt as omitted,
// which recovery never rehydrates, not as an unconfirmed skip.
func TestPromptVetoOmitsThePrompt(t *testing.T) {
	vetoed := payloadcapture.DefaultRuntimeConfiguration()
	vetoed.PromptVeto = true
	if got := CaptureTurnPrompt("deploy the thing", vetoed); got.Mode != TurnPromptOmitted {
		t.Fatalf("vetoed prompt mode = %q", got.Mode)
	}
	if got := CaptureTurnPrompt("deploy the thing", payloadcapture.DefaultRuntimeConfiguration()); got.Mode != TurnPromptSkipped {
		t.Fatalf("unconfirmed prompt mode = %q", got.Mode)
	}
}

// A turn the prompt hook missed, found only in the transcript, is refused
// under a held opt-out too: unconfirmed, it would be recoverable after a
// later opt-in.
func TestPromptVetoRefusesTranscriptOnlyTurns(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	vetoed := payloadcapture.DefaultRuntimeConfiguration()
	vetoed.PromptVeto = true
	s.SetPayloadCaptureConfiguration(vetoed)
	if _, err := s.EnsureObservedSessionWithMode(ctx, "s1", "claude", dir, "observe"); err != nil {
		t.Fatal(err)
	}
	transcript := filepath.Join(dir, "s1.jsonl")
	line := fmt.Sprintf(`{"type":"user","sessionId":"s1","timestamp":%q,"message":{"content":"deploy the thing"}}`, time.Now().UTC().Add(-time.Minute).Format(time.RFC3339Nano)) + "\n"
	if err := os.WriteFile(transcript, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.TrackToolTranscript(ctx, hook.Event{SessionID: "s1", Agent: "claude", HookName: hook.HookPostToolUse, TranscriptPath: transcript}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReconcileToolUsage(ctx); err != nil {
		t.Fatal(err)
	}
	var allowed sql.NullInt64
	if err := s.db.QueryRow(`select capture_allowed from tool_usage_prompts where session_id='s1'`).Scan(&allowed); err != nil {
		t.Fatal(err)
	}
	if !allowed.Valid || allowed.Int64 != 0 {
		t.Fatalf("capture_allowed = %+v, want 0", allowed)
	}
}
