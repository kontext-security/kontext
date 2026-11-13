package managedstream

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func TestMerlinUploadsAfterActionAndRetriesWithoutMutableFeedback(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")
	saveTestDecision(t, store, "session-1", "toolu_2")
	actions, err := store.AuthorizationActions(context.Background(), sqlite.LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var actionID, laterActionID string
	for _, action := range actions {
		if action["canonical_event_type"] != "request.decided" {
			continue
		}
		if action["tool_use_id"] == "toolu_1" {
			actionID = action["id"].(string)
		} else {
			laterActionID = action["id"].(string)
		}
	}
	ageTestActionCursor(t, dbPath, actionID)
	ageTestActionCursor(t, dbPath, laterActionID)
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
	// "Full tool calls and prompts" until the workspace moves off it below.
	promptsAllowed := true
	capture := func() payloadcapture.RuntimeConfiguration {
		mode := payloadcapture.ModeSummary
		if promptsAllowed {
			mode = payloadcapture.ModeFull
		}
		return payloadcapture.RuntimeConfiguration{ConfiguredMode: mode, EffectiveMode: mode, ConfigIdentity: strings.Repeat("c", 64), Confirmed: true, WorkTypeClassification: promptsAllowed}
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
			if annotation.SchemaVersion != fixture.SchemaVersion || (annotation.ReviewContext != nil) != promptsAllowed || annotation.UserFeedback != "" || annotation.FeedbackAt != nil {
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
	opts := Options{CaptureConfiguration: capture, DBPath: dbPath, StatePath: statePath, CloudURL: server.URL, InstallationID: "ins_0123456789abcdefghijklmnopqrstuv", InstallToken: "test-token", HTTPClient: server.Client(), BatchLimit: 1}
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

	// A context stored on the top step stays on the laptop once the workspace
	// moves off it, though its annotation had not left yet (ENG-1045).
	promptsAllowed = false
	later := fixture.StepSafetyRecord
	later.ActionID = laterActionID
	later.ToolUseID = "toolu_2"
	later.ID = "ssv_22345678-1234-1234-1234-123456789012"
	later.CreatedAt = time.Now().UTC()
	if later.ReviewContext == nil {
		t.Fatal("fixture carries no review context")
	}
	if _, err := store.SaveStepSafetyVerdict(context.Background(), later); err != nil {
		t.Fatal(err)
	}
	if err := Flush(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if annotationPosts != 3 {
		t.Fatalf("annotation after the move not uploaded: %d", annotationPosts)
	}
}
