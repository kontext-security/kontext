package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/guard/risk"
)

func TestLedgerLag(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	first, err := store.SaveDecision(ctx, risk.HookEvent{SessionID: "s1", HookEventName: "SessionStart"}, risk.RiskDecision{Decision: risk.DecisionAllow, Reason: "ok", ReasonCode: "normal_tool_call", RiskEvent: risk.RiskEvent{Type: risk.EventNormalToolCall}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.SaveDecision(ctx, risk.HookEvent{SessionID: "s1", HookEventName: "PostToolUse", ToolName: "Read", ToolUseID: "tool-1"}, risk.RiskDecision{Decision: risk.DecisionAllow, Reason: "ok", ReasonCode: "normal_tool_call", RiskEvent: risk.RiskEvent{Type: risk.EventNormalToolCall}})
	if err != nil {
		t.Fatal(err)
	}
	third, err := store.SaveDecision(ctx, risk.HookEvent{SessionID: "s1", HookEventName: "SessionEnd"}, risk.RiskDecision{Decision: risk.DecisionAllow, Reason: "ok", ReasonCode: "normal_tool_call", RiskEvent: risk.RiskEvent{Type: risk.EventNormalToolCall}})
	if err != nil {
		t.Fatal(err)
	}

	times := []time.Time{
		time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC),
		time.Date(2026, 7, 9, 10, 5, 0, 0, time.UTC),
		time.Date(2026, 7, 9, 10, 10, 0, 0, time.UTC),
	}
	ids := []string{first.ID, second.ID, third.ID}
	for i, id := range ids {
		if _, err := store.db.ExecContext(ctx, `
update authorization_actions
set updated_at = ?,
    updated_at_cursor_key = ?
where id = ?
		`, times[i].Format(time.RFC3339Nano), ledgerTimestampCursorKeyFromTime(times[i]), id); err != nil {
			t.Fatal(err)
		}
	}

	newest, pending, err := LedgerLag(ctx, dbPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if newest == nil || !newest.Equal(times[2]) || pending != 3 {
		t.Fatalf("LedgerLag nil cursor = newest %v pending %d, want %v and 3", newest, pending, times[2])
	}

	newest, pending, err = LedgerLag(ctx, dbPath, &LedgerCursor{UpdatedAt: times[1], ActionID: second.ID})
	if err != nil {
		t.Fatal(err)
	}
	if newest == nil || !newest.Equal(times[2]) || pending != 1 {
		t.Fatalf("LedgerLag mid cursor = newest %v pending %d, want %v and 1", newest, pending, times[2])
	}

	newest, pending, err = LedgerLag(ctx, dbPath, &LedgerCursor{UpdatedAt: times[2], ActionID: third.ID})
	if err != nil {
		t.Fatal(err)
	}
	if newest == nil || !newest.Equal(times[2]) || pending != 0 {
		t.Fatalf("LedgerLag past cursor = newest %v pending %d, want %v and 0", newest, pending, times[2])
	}

	newest, pending, err = LedgerLag(ctx, filepath.Join(t.TempDir(), "missing.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if newest != nil || pending != 0 {
		t.Fatalf("LedgerLag missing DB = newest %v pending %d, want nil and 0", newest, pending)
	}
}
