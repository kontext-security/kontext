package sqlite

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPruneExportedLedgerDeletesOnlyAcceptedOldRows(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Now().UTC()
	base := now.Add(-60 * 24 * time.Hour)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"act_old_1", "act_old_2", "act_skipped", "act_big", "act_risk_pending", "act_risk_done", "act_merlin_pending"} {
		insertLedgerTestAction(t, tx, id, base.Add(time.Duration(i)*time.Second))
		insertLedgerTestReceipt(t, tx, "rcpt_"+id, id, base.Add(time.Duration(i)*time.Second))
	}
	// Exported long ago but after the persisted cursor.
	insertLedgerTestAction(t, tx, "act_unexported", base.Add(20*24*time.Hour))
	insertLedgerTestAction(t, tx, "act_recent", now.Add(-24*time.Hour))
	// The newest receipt is the chain head and belongs to a prunable action.
	insertLedgerTestReceipt(t, tx, "rcpt_head", "act_old_1", base.Add(time.Minute))
	if _, err := tx.ExecContext(ctx, `update authorization_actions set tool_output_captured_json = ? where id = 'act_big'`, strings.Repeat("x", 2048)); err != nil {
		t.Fatal(err)
	}
	for _, annotation := range []struct{ id, actionID string }{{"rta_pending", "act_risk_pending"}, {"rta_done", "act_risk_done"}} {
		created := base
		if annotation.id == "rta_pending" {
			created = base.Add(time.Hour)
		}
		if _, err := tx.ExecContext(ctx, `insert into risk_type_annotations(id, action_id, session_id, command_hash, input_kind, schema_version, model_version, annotation_json, created_at)
values(?, ?, 'session-1', 'h', 'shell', 'v1', 'm1', '{}', ?)`, annotation.id, annotation.actionID, created.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `insert into step_safety_verdicts(id, action_id, session_id, tool_name, shadow_decision, threshold, model_version, latency_ms, created_at)
values('ssv_pending', 'act_merlin_pending', 'session-1', 'Bash', 'allow', 0.5, 'm1', 1, ?)`, base.Add(time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordLedgerExportSkips(ctx, []string{"act_skipped"}, "body too large"); err != nil {
		t.Fatal(err)
	}

	riskCursor, merlinCursor := base.Add(time.Minute), base.Add(time.Minute)
	opts := LedgerPruneOptions{
		ActionsExportedBefore: base.Add(10 * 24 * time.Hour),
		RiskTypeCreatedAfter:  &riskCursor,
		MerlinCreatedAfter:    &merlinCursor,
		OlderThan:             now.Add(-30 * 24 * time.Hour),
		MaxRowBytes:           1024,
		Limit:                 100,
	}
	pruned, err := store.PruneExportedLedger(ctx, opts)
	if err != nil || pruned != 3 {
		t.Fatalf("pruned %d, err %v; want act_old_1, act_old_2, act_risk_done", pruned, err)
	}
	actions, err := store.queryStrings(ctx, `select id from authorization_actions order by id`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"act_big", "act_merlin_pending", "act_recent", "act_risk_pending", "act_skipped", "act_unexported"}
	if !slices.Equal(actions, want) {
		t.Fatalf("remaining actions = %v, want %v", actions, want)
	}
	receipts, err := store.queryStrings(ctx, `select id from authorization_receipts order by id`)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"rcpt_act_big", "rcpt_act_merlin_pending", "rcpt_act_risk_pending", "rcpt_act_skipped", "rcpt_head"}
	if !slices.Equal(receipts, want) {
		t.Fatalf("remaining receipts = %v, want %v", receipts, want)
	}
	// The next receipt still chains from the previous head.
	tx, err = store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	head, err := previousReceiptHash(ctx, tx)
	_ = tx.Rollback()
	if err != nil || head != "hash_rcpt_head" {
		t.Fatalf("chain head = %q, %v", head, err)
	}

	// Once the annotations are exported, their actions become prunable too;
	// the newest local history stays.
	later := base.Add(2 * time.Hour)
	opts.RiskTypeCreatedAfter, opts.MerlinCreatedAfter = &later, &later
	opts.ActionsExportedBefore = now
	if pruned, err := store.PruneExportedLedger(ctx, opts); err != nil || pruned != 3 {
		t.Fatalf("second prune %d, err %v; want both annotated actions and act_unexported", pruned, err)
	}
	actions, err = store.queryStrings(ctx, `select id from authorization_actions order by id`)
	if err != nil || !slices.Equal(actions, []string{"act_big", "act_recent", "act_skipped"}) {
		t.Fatalf("remaining actions = %v, err %v", actions, err)
	}
}

func TestPruneExportedLedgerRequiresCursorAndHonorsLimit(t *testing.T) {
	ctx := context.Background()
	store, err := OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Now().UTC().Add(-60 * 24 * time.Hour)
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"act_1", "act_2", "act_3"} {
		insertLedgerTestAction(t, tx, id, base.Add(time.Duration(i)*time.Second))
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	opts := LedgerPruneOptions{OlderThan: time.Now(), MaxRowBytes: 1 << 20, Limit: 2}
	if pruned, err := store.PruneExportedLedger(ctx, opts); err != nil || pruned != 0 {
		t.Fatalf("pruned %d without an export cursor, err %v", pruned, err)
	}
	opts.ActionsExportedBefore = time.Now()
	if pruned, err := store.PruneExportedLedger(ctx, opts); err != nil || pruned != 2 {
		t.Fatalf("pruned %d, err %v; want the limit", pruned, err)
	}
	actions, err := store.queryStrings(ctx, `select id from authorization_actions`)
	if err != nil || !slices.Equal(actions, []string{"act_3"}) {
		t.Fatalf("oldest rows must go first: %v %v", actions, err)
	}
}
