package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"testing"
	"time"
)

func TestAuthorizationActionsByIDsChunksBeyondSQLiteVariableLimit(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	insertLedgerTestAction(t, tx, "act_32999", base)
	insertLedgerTestAction(t, tx, "act_00020", base.Add(time.Second))
	insertLedgerTestAction(t, tx, "act_16000", base.Add(2*time.Second))
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	ids := make([]string, 33_000)
	for i := range ids {
		ids[i] = fmt.Sprintf("act_%05d", i)
	}
	records, err := store.authorizationActionsByIDs(context.Background(), ids)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"act_32999", "act_00020", "act_16000"}
	if len(records) != len(want) {
		t.Fatalf("records = %d, want %d", len(records), len(want))
	}
	for i, record := range records {
		if record["id"] != want[i] {
			t.Fatalf("record %d id = %v, want %s", i, record["id"], want[i])
		}
		if _, ok := record[ledgerCursorUpdatedAtKeyColumn]; ok {
			t.Fatalf("record %d leaked cursor key", i)
		}
	}
}

func TestAuthorizationActionsByIDsOrdersMergedChunks(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	const total = 1_100
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	order := rand.New(rand.NewSource(1)).Perm(total)
	ids := make([]string, 0, total)
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range order {
		id := fmt.Sprintf("act_%04d", i)
		insertLedgerTestAction(t, tx, id, base.Add(time.Duration(i)*time.Second))
		ids = append(ids, id)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	records, err := store.authorizationActionsByIDs(context.Background(), ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != total {
		t.Fatalf("records = %d, want %d", len(records), total)
	}
	for i, record := range records {
		want := fmt.Sprintf("act_%04d", i)
		if record["id"] != want {
			t.Fatalf("record %d id = %v, want %s", i, record["id"], want)
		}
	}
}

// created_at is RFC3339Nano text, which trims trailing zeros, so it does not
// sort by time: "...:20.87Z" sorts after "...:20.871Z" because 'Z' > '1'.
// Windows' coarse clock makes such stamps common. The ids run against time,
// so the tiebreak cannot produce the order by chance.
func TestAgentSessionsOrderByCreatedAtTime(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, session := range []struct{ id, createdAt string }{
		{"session-a", "2026-10-19T10:00:20.871Z"},
		{"session-b", "2026-10-19T10:00:20.87Z"},
		{"session-c", "2026-10-19T10:00:20.5Z"},
		{"session-d", "2026-10-19T10:00:20Z"},
		{"session-e", "2026-10-19T10:00:20.87Z"}, // ties with session-b
	} {
		if _, err := store.EnsureObservedSession(ctx, session.id, "claude", "/tmp"); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.ExecContext(ctx, `update agent_sessions set created_at = ? where id = ?`, session.createdAt, session.id); err != nil {
			t.Fatal(err)
		}
	}
	sessions, err := store.AgentSessions(ctx, []string{"session-a", "session-b", "session-c", "session-d", "session-e"})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, session := range sessions {
		got = append(got, session["id"].(string))
	}
	if want := []string{"session-d", "session-c", "session-b", "session-e", "session-a"}; !slices.Equal(got, want) {
		t.Fatalf("sessions = %v, want %v", got, want)
	}
	// Only the order changes: the text on the wire stays RFC3339Nano.
	if created := sessions[0]["created_at"]; created != "2026-10-19T10:00:20Z" {
		t.Fatalf("created_at = %v, want RFC3339Nano text", created)
	}
}

func TestLedgerBatchReturnsCursorWhenReceiptRangeExceedsLimit(t *testing.T) {
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	insertLedgerTestAction(t, tx, "act_selected_1", base)
	insertLedgerTestAction(t, tx, "act_selected_2", base.Add(time.Second))
	insertLedgerTestAction(t, tx, "act_foreign", base.Add(2*time.Second))
	insertLedgerTestReceipt(t, tx, "rcpt_selected_1", "act_selected_1", base)
	insertLedgerTestReceipt(t, tx, "rcpt_foreign_1", "act_foreign", base.Add(time.Second))
	insertLedgerTestReceipt(t, tx, "rcpt_foreign_2", "act_foreign", base.Add(2*time.Second))
	insertLedgerTestReceipt(t, tx, "rcpt_selected_2", "act_selected_2", base.Add(3*time.Second))
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	batch, err := store.LedgerBatch(context.Background(), LedgerExportOptions{Limit: 2, ReceiptLimit: 3})
	if !errors.Is(err, ErrLedgerReceiptRangeTooLarge) {
		t.Fatalf("LedgerBatch() error = %v, want ErrLedgerReceiptRangeTooLarge", err)
	}
	if batch.Cursor == nil {
		t.Fatal("LedgerBatch() cursor = nil")
	}
	if len(batch.Actions) != 2 || len(batch.Sessions) != 0 || len(batch.Receipts) != 0 {
		t.Fatalf("batch sizes = actions %d sessions %d receipts %d", len(batch.Actions), len(batch.Sessions), len(batch.Receipts))
	}
}

func insertLedgerTestAction(t *testing.T, tx *sql.Tx, id string, updatedAt time.Time) {
	t.Helper()
	timestamp := updatedAt.Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(context.Background(), `
insert into authorization_actions(
  id, session_id, canonical_event_type, status, created_at, updated_at, updated_at_cursor_key
) values(?, 'session-1', 'request.observed', 'completed', ?, ?, ?)
	`, id, timestamp, timestamp, ledgerTimestampCursorKeyFromTime(updatedAt)); err != nil {
		t.Fatal(err)
	}
}

func insertLedgerTestReceipt(t *testing.T, tx *sql.Tx, id, actionID string, createdAt time.Time) {
	t.Helper()
	if _, err := tx.ExecContext(context.Background(), `
insert into authorization_receipts(
  id, action_id, session_id, receipt_type, receipt_payload_json, receipt_hash, created_at
) values(?, ?, 'session-1', 'observed', '{}', ?, ?)
	`, id, actionID, "hash_"+id, createdAt.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}
