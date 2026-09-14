package managedstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
)

func TestMerlinUploadsAfterActionAndRetriesWithoutMutableFeedback(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")
	actions, err := store.AuthorizationActions(context.Background(), sqlite.LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var actionID string
	for _, action := range actions {
		if action["canonical_event_type"] == "request.decided" {
			actionID = action["id"].(string)
		}
	}
	ageTestActionCursor(t, dbPath, actionID)
	data, err := os.ReadFile("testdata/merlin-annotation.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture sqlite.MerlinAnnotationRecord
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	fixture.ActionID = actionID
	fixture.CreatedAt = time.Now().Add(-time.Minute).UTC()
	if _, err := store.SaveStepSafetyVerdict(context.Background(), fixture.StepSafetyRecord); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetStepSafetyFeedback(context.Background(), actionID, "should_allow"); err != nil {
		t.Fatal(err)
	}
	knownActions := map[string]bool{}
	posts, annotationPosts := 0, 0
	rejectFirst := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Payload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		posts++
		for _, action := range payload.Actions {
			knownActions[action["id"].(string)] = true
		}
		for _, annotation := range payload.MerlinAnnotations {
			annotationPosts++
			if !knownActions[annotation.ActionID] {
				t.Error("annotation arrived before action")
			}
			if annotation.SchemaVersion != fixture.SchemaVersion || annotation.ReviewContext == nil || annotation.UserFeedback != "" || annotation.FeedbackAt != nil {
				t.Errorf("wire record: %+v", annotation)
			}
			if rejectFirst {
				rejectFirst = false
				w.WriteHeader(503)
				return
			}
		}
		w.WriteHeader(200)
	}))
	defer server.Close()
	statePath := filepath.Join(t.TempDir(), "state.json")
	opts := Options{DBPath: dbPath, StatePath: statePath, CloudURL: server.URL, InstallationID: "ins_0123456789abcdefghijklmnopqrstuv", InstallToken: "test-token", HTTPClient: server.Client(), BatchLimit: 1}
	if err := Flush(context.Background(), opts); err == nil {
		t.Fatal("expected retryable upload failure")
	}
	state, err := LoadState(statePath)
	if err != nil || state.MerlinCreatedAfter != nil {
		t.Fatalf("failed upload advanced cursor: %+v / %v", state, err)
	}
	if err := Flush(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	state, err = LoadState(statePath)
	if err != nil || state.MerlinCreatedAfter == nil || state.MerlinAnnotationID != fixture.ID {
		t.Fatalf("cursor not persisted: %+v / %v", state, err)
	}
	if posts < 3 || annotationPosts != 2 {
		t.Fatalf("posts=%d annotations=%d", posts, annotationPosts)
	}
	// Reopening and flushing the acknowledged stream must not repeat the annotation.
	if err := Flush(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if annotationPosts != 2 {
		t.Fatalf("acknowledged annotation repeated: %d", annotationPosts)
	}
}
