package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/riskclassifier"
)

func TestImpactLegacyUpgradeAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "guard.db")
	legacy, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`create table risk_classifier_verdicts (
		id text primary key, action_id text not null, session_id text not null,
		command_redacted text not null, command_hash text not null, created_at text not null)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	model, err := riskclassifier.LoadImpactModel()
	if err != nil {
		t.Fatal(err)
	}
	record := sampleClassifierRecord()
	annotation := model.Classify(`pkill -f "apps/web/server.js"`)
	record.Impact = &annotation
	if _, err := store.SaveClassifierVerdict(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	old := sampleClassifierRecord()
	old.ActionID = "act_legacy_without_impact"
	if _, err := store.SaveClassifierVerdict(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	rows, err := store.ClassifierVerdictsForSession(context.Background(), record.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d", len(rows))
	}
	want, _ := json.Marshal(annotation)
	for _, row := range rows {
		if row.ActionID == old.ActionID {
			if row.Impact != nil {
				t.Fatal("invented legacy annotation")
			}
			continue
		}
		got, _ := json.Marshal(row.Impact)
		if string(got) != string(want) {
			t.Fatalf("annotation changed on reopen: %s", got)
		}
	}
}
