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
	for i, id := range []string{"act_interleaved", "act_old_1", "act_skipped", "act_big", "act_risk_pending", "act_risk_done", "act_merlin_pending"} {
		insertLedgerTestAction(t, tx, id, base.Add(time.Duration(i)*time.Second))
		insertLedgerTestReceipt(t, tx, "rcpt_"+id, id, base.Add(time.Duration(i)*time.Second))
	}
	// Exported long ago but after the persisted cursor.
	insertLedgerTestAction(t, tx, "act_unexported", base.Add(20*24*time.Hour))
	// Exported before the hosted ledger reported alterations.
	insertLedgerTestAction(t, tx, "act_unverified", base.Add(-24*time.Hour))
	insertLedgerTestAction(t, tx, "act_recent", now.Add(-24*time.Hour))
	// Receipts of other actions sit inside this action's receipt range, so an
	// older client may have skipped its minimum batch as too wide.
	insertLedgerTestReceipt(t, tx, "rcpt_act_interleaved_2", "act_interleaved", base.Add(time.Minute))
	// The newest receipt is the chain head and belongs to a prunable action.
	insertLedgerTestAction(t, tx, "act_old_2", base.Add(10*time.Second))
	insertLedgerTestReceipt(t, tx, "rcpt_act_old_2", "act_old_2", base.Add(2*time.Minute))
	insertLedgerTestReceipt(t, tx, "rcpt_head", "act_old_2", base.Add(3*time.Minute))
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
	verifiedAfter := base.Add(-time.Hour)
	opts := LedgerPruneOptions{
		ActionsExportedBefore: base.Add(10 * 24 * time.Hour),
		VerifiedAfter:         &verifiedAfter,
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
	actions, err := queryStrings(ctx, store.db, `select id from authorization_actions order by id`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"act_big", "act_interleaved", "act_merlin_pending", "act_recent", "act_risk_pending", "act_skipped", "act_unexported", "act_unverified"}
	if !slices.Equal(actions, want) {
		t.Fatalf("remaining actions = %v, want %v", actions, want)
	}
	receipts, err := queryStrings(ctx, store.db, `select id from authorization_receipts order by id`)
	if err != nil {
		t.Fatal(err)
	}
	want = []string{"rcpt_act_big", "rcpt_act_interleaved", "rcpt_act_interleaved_2", "rcpt_act_merlin_pending", "rcpt_act_risk_pending", "rcpt_act_skipped", "rcpt_head"}
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
	actions, err = queryStrings(ctx, store.db, `select id from authorization_actions order by id`)
	if err != nil || !slices.Equal(actions, []string{"act_big", "act_interleaved", "act_recent", "act_skipped", "act_unverified"}) {
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
	if pruned, err := store.PruneExportedLedger(ctx, opts); err != nil || pruned != 0 {
		t.Fatalf("pruned %d before the hosted ledger reported alterations, err %v", pruned, err)
	}
	verifiedAfter := base.Add(-time.Hour)
	opts.VerifiedAfter = &verifiedAfter
	if pruned, err := store.PruneExportedLedger(ctx, opts); err != nil || pruned != 2 {
		t.Fatalf("pruned %d, err %v; want the limit", pruned, err)
	}
	actions, err := queryStrings(ctx, store.db, `select id from authorization_actions`)
	if err != nil || !slices.Equal(actions, []string{"act_3"}) {
		t.Fatalf("oldest rows must go first: %v %v", actions, err)
	}
}

func TestPruneExportedLedgerRechecksCandidatesUnderLock(t *testing.T) {
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
	for i, id := range []string{"act_annotated_meanwhile", "act_plain"} {
		insertLedgerTestAction(t, tx, id, base.Add(time.Duration(i)*time.Second))
		insertLedgerTestReceipt(t, tx, "rcpt_"+id, id, base.Add(time.Duration(i)*time.Second))
	}
	insertLedgerTestReceipt(t, tx, "rcpt_head", "act_plain", base.Add(time.Minute))
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// An enrichment run annotates an old action after it was picked as a
	// candidate; the annotation is not exported yet.
	t.Cleanup(func() { pruneCandidatesFound = func() {} })
	pruneCandidatesFound = func() {
		if _, err := store.db.ExecContext(ctx, `insert into risk_type_annotations(id, action_id, session_id, command_hash, input_kind, schema_version, model_version, annotation_json, created_at)
values('rta_new', 'act_annotated_meanwhile', 'session-1', 'h', 'shell', 'v1', 'm1', '{}', ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	exported := base.Add(time.Hour)
	verifiedAfter := base.Add(-time.Hour)
	pruned, err := store.PruneExportedLedger(ctx, LedgerPruneOptions{
		ActionsExportedBefore: time.Now(),
		VerifiedAfter:         &verifiedAfter,
		RiskTypeCreatedAfter:  &exported,
		OlderThan:             time.Now().Add(-30 * 24 * time.Hour),
		MaxRowBytes:           1 << 20,
		Limit:                 10,
	})
	if err != nil || pruned != 1 {
		t.Fatalf("pruned %d, err %v; want only act_plain", pruned, err)
	}
	actions, err := queryStrings(ctx, store.db, `select id from authorization_actions`)
	if err != nil || !slices.Equal(actions, []string{"act_annotated_meanwhile"}) {
		t.Fatalf("remaining actions = %v, err %v", actions, err)
	}
}
