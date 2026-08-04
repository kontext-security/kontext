package managedstream

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
)

func TestDefaultTimeoutFromEnv(t *testing.T) {
	t.Setenv(envTimeout, "")
	if got := DefaultTimeoutFromEnv(); got != 30*time.Second {
		t.Fatalf("DefaultTimeoutFromEnv() = %s, want 30s", got)
	}

	t.Setenv(envTimeout, "45s")
	if got := DefaultTimeoutFromEnv(); got != 45*time.Second {
		t.Fatalf("DefaultTimeoutFromEnv(valid) = %s, want 45s", got)
	}

	t.Setenv(envTimeout, "garbage")
	if got := DefaultTimeoutFromEnv(); got != DefaultTimeout {
		t.Fatalf("DefaultTimeoutFromEnv(invalid) = %s, want %s", got, DefaultTimeout)
	}
}

func TestFlushPostsLedgerBatchWithInstallationIdentity(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var got wireBatch
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		DeviceLabel:    "michel-macbook",
		UserEmail:      " anna@katana.com ",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got.BatchVersion != "v1" {
		t.Fatalf("batch_version = %q, want v1", got.BatchVersion)
	}
	if got.InstallationID != "ins_0123456789abcdefghijklmnopqrstuv" {
		t.Fatalf("installation_id = %q", got.InstallationID)
	}
	if got.Device == nil || got.Device.Label != "michel-macbook" {
		t.Fatalf("device = %+v", got.Device)
	}
	if got.Device.UserEmail != "anna@katana.com" {
		t.Fatalf("device user_email = %q, want trimmed anna@katana.com", got.Device.UserEmail)
	}
	if len(got.Sessions) != 1 || len(got.Actions) != 2 || len(got.Receipts) != 2 {
		t.Fatalf("batch counts = sessions %d actions %d receipts %d", len(got.Sessions), len(got.Actions), len(got.Receipts))
	}
	if got.Actions[0]["event_type"] != "request.proposed" ||
		got.Actions[1]["event_type"] != "request.decided" ||
		got.Actions[1]["decision_result"] != "allow" {
		t.Fatalf("actions = %+v, want proposed and decided ledger events", got.Actions)
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil {
		t.Fatal("updated_after was not persisted")
	}
	if state.LastHeartbeatAttemptAt == "" || state.LastHeartbeatAt == "" {
		t.Fatalf("heartbeat state = %+v, want ledger success to count as heartbeat", state)
	}
}

func TestFlushOmitsBlankDeviceLabel(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var got wireBatch
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		DeviceLabel:    " \t\n ",
		UserEmail:      " \t\n ",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got.Device != nil {
		t.Fatalf("device = %+v, want omitted", got.Device)
	}
}

func TestFlushEmitsDeviceForUserEmailAlone(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var got wireBatch
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		UserEmail:      "anna@katana.com",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got.Device == nil || got.Device.UserEmail != "anna@katana.com" || got.Device.Label != "" {
		t.Fatalf("device = %+v, want user_email only", got.Device)
	}
}

func TestFlushResolvesDeploymentVersionPerFlush(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var got wireBatch
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	version := "  0.2.0  "
	flushOpts := func() Options {
		return Options{
			DBPath:            dbPath,
			StatePath:         filepath.Join(t.TempDir(), "stream-state.json"),
			CloudURL:          server.URL,
			InstallationID:    "ins_0123456789abcdefghijklmnopqrstuv",
			InstallToken:      "test-install-token",
			DeploymentVersion: func() string { return version },
			HTTPClient:        server.Client(),
		}
	}

	if err := Flush(context.Background(), flushOpts()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if got.Device == nil || got.Device.DeploymentVersion != "0.2.0" {
		t.Fatalf("device = %+v, want deployment_version 0.2.0", got.Device)
	}

	// A later flush reflects a marker change (e.g. in-place upgrade) without
	// rebuilding the daemon's options. Fresh state path re-posts the decision.
	version = "0.3.0"
	if err := Flush(context.Background(), flushOpts()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if got.Device == nil || got.Device.DeploymentVersion != "0.3.0" {
		t.Fatalf("device = %+v, want deployment_version 0.3.0", got.Device)
	}
}

func TestFlushDoesNotAdvanceCursorWhenHostedBackendFails(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	}); err == nil {
		t.Fatal("Flush() error = nil, want hosted failure")
	}

	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file error = %v, want not exist", err)
	}
}

func TestFlushCapsBatchLimitBeforePosting(t *testing.T) {
	store, dbPath := testStore(t)
	for i := 0; i < 80; i++ {
		saveTestDecision(t, store, fmt.Sprintf("session-%03d", i), fmt.Sprintf("toolu_%03d", i))
	}

	var got wireBatch
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1000,
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if len(got.Actions) > DefaultBatchLimit {
		t.Fatalf("posted %d actions, want at most %d", len(got.Actions), DefaultBatchLimit)
	}
}

func TestFlushDrainsBacklogInOneCall(t *testing.T) {
	store, dbPath := testStore(t)
	// 5 decisions -> 10 action rows; with a batch limit of 4 the backlog
	// needs 3 posts. One Flush call must ship all of them, not one per tick.
	for i := 0; i < 5; i++ {
		saveTestDecision(t, store, fmt.Sprintf("session-%03d", i), fmt.Sprintf("toolu_%03d", i))
	}

	var mu sync.Mutex
	var posts int
	shipped := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload wireBatch
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		mu.Lock()
		posts++
		for _, action := range payload.Actions {
			if id, ok := action["id"].(string); ok {
				shipped[id] = true
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     4,
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	// Batches may overlap (receipt-chain continuity pulls referenced actions
	// into a page), so assert distinct coverage rather than summed counts.
	if len(shipped) != 10 {
		t.Fatalf("shipped %d distinct actions in one Flush, want the whole backlog (10)", len(shipped))
	}
	if posts != 3 {
		t.Fatalf("posts = %d, want 3 cursor pages of at most 4 actions", posts)
	}
}

func TestFlushReexportsRowsThatCommitAfterCursorAdvance(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	var mu sync.Mutex
	shippedToolUseIDs := map[string]bool{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload wireBatch
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		mu.Lock()
		for _, action := range payload.Actions {
			if id, ok := action["tool_call_id"].(string); ok {
				shippedToolUseIDs[id] = true
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	flush := func() {
		t.Helper()
		if err := Flush(context.Background(), Options{
			DBPath:         dbPath,
			StatePath:      statePath,
			CloudURL:       server.URL,
			InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
			InstallToken:   "test-install-token",
			HTTPClient:     server.Client(),
		}); err != nil {
			t.Fatalf("Flush() error = %v", err)
		}
	}

	flush()

	// Simulate the concurrency race: a hook write captures its timestamp
	// before the flush above reads the queue, but only COMMITs afterwards.
	// Its cursor key then sorts BEFORE the cursor the flush persisted.
	saveTestDecision(t, store, "session-1", "toolu_late")
	backdated := time.Now().UTC().Add(-5 * time.Second).Format("2006-01-02T15:04:05.000000000Z07:00")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if _, err := db.Exec(
		`update authorization_actions set updated_at_cursor_key = ? where tool_use_id = 'toolu_late'`,
		backdated,
	); err != nil {
		t.Fatalf("backdate cursor key: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	flush()

	mu.Lock()
	defer mu.Unlock()
	if !shippedToolUseIDs["toolu_late"] {
		t.Fatal("late-committed row was never exported: strict cursor skipped it")
	}
}

func TestCursorAdvancesIsMonotonic(t *testing.T) {
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	persisted := State{UpdatedAfter: &base, ActionID: "act_b"}

	if cursorAdvances(persisted, base.Add(-time.Second), "act_z") {
		t.Fatal("cursor must not regress behind the persisted timestamp (poison-row skip would be undone)")
	}
	if cursorAdvances(persisted, base, "act_a") {
		t.Fatal("cursor must not regress behind the persisted id tiebreak")
	}
	if !cursorAdvances(persisted, base, "act_c") {
		t.Fatal("same timestamp with a later id must advance")
	}
	if !cursorAdvances(persisted, base.Add(time.Second), "") {
		t.Fatal("later timestamp must advance")
	}
	if !cursorAdvances(State{}, base, "act_a") {
		t.Fatal("empty state must always advance")
	}
}

func TestFlushRetriesWithSmallerBatchWhenHostedBackendRejectsSize(t *testing.T) {
	store, dbPath := testStore(t)
	for i := 0; i < 4; i++ {
		saveTestDecision(t, store, fmt.Sprintf("session-%03d", i), fmt.Sprintf("toolu_%03d", i))
	}

	var actionCounts []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got wireBatch
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		actionCounts = append(actionCounts, len(got.Actions))
		if len(actionCounts) == 1 {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, _ = w.Write([]byte(`{"message":"payload too large"}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     4,
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	// The first post is rejected (413) and retried at half size; after an
	// accepted retry, later batches grow again while draining the full backlog.
	if len(actionCounts) < 3 {
		t.Fatalf("action counts = %v, want rejected post, smaller retry, and recovered batch", actionCounts)
	}
	if actionCounts[0] <= actionCounts[1] {
		t.Fatalf("action counts = %v, want retry with a smaller batch", actionCounts)
	}
	accepted := 0
	recovered := false
	for _, count := range actionCounts[1:] {
		accepted += count
		if count > actionCounts[1] {
			recovered = true
		}
	}
	// Pages can overlap via receipt-chain continuity, so require at least
	// full coverage of the 8-action backlog.
	if accepted < 8 {
		t.Fatalf("accepted %d actions, want at least the whole backlog (8)", accepted)
	}
	if !recovered {
		t.Fatalf("action counts = %v, want batch limit to recover after smaller retry", actionCounts)
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil {
		t.Fatal("updated_after was not persisted after smaller retry")
	}
}

func TestFlushDoesNotRetrySmallerBatchForHostedValidation(t *testing.T) {
	store, dbPath := testStore(t)
	for i := 0; i < 4; i++ {
		saveTestDecision(t, store, fmt.Sprintf("session-%03d", i), fmt.Sprintf("toolu_%03d", i))
	}

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"organization_id does not match installation"}`))
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     4,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want hosted validation failure")
	}
	if requests != 1 {
		t.Fatalf("request count = %d, want 1 terminal attempt", requests)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file error = %v, want not exist", err)
	}
}

func TestFlushReportsHostedValidationBody(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"authorization_actions must contain no more than 1000 records"}`))
	}))
	t.Cleanup(server.Close)

	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want hosted validation failure")
	}
	if !strings.Contains(err.Error(), "status 400") ||
		!strings.Contains(err.Error(), "authorization_actions must contain no more than 1000 records") {
		t.Fatalf("Flush() error = %q, want status and response body", err.Error())
	}
}

func TestFlushRedactsHostedValidationBody(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"api_key":"raw-api-key","client_secret":"raw-client-secret","install_token":"raw-install-token","password":"raw-password","secret":"raw-secret","token":"raw-token","message":"Bearer raw-bearer"}`))
	}))
	t.Cleanup(server.Close)

	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      filepath.Join(t.TempDir(), "stream-state.json"),
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want hosted validation failure")
	}
	for _, secret := range []string{
		"raw-api-key",
		"raw-client-secret",
		"raw-install-token",
		"raw-password",
		"raw-secret",
		"raw-token",
		"raw-bearer",
	} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("Flush() error = %q, want %q redacted", err.Error(), secret)
		}
	}
	if !strings.Contains(err.Error(), "[REDACTED]") {
		t.Fatalf("Flush() error = %q, want hosted body secrets redacted", err.Error())
	}
}

func TestFlushDoesNotAdvanceCursorPastHostedRejectedMinimumBatch(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"message":"schema validation failed"}`))
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want hosted validation failure")
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file error = %v, want not exist", err)
	}
}

func TestFlushDoesNotAdvanceCursorPastHostedTooLargeMinimumBatch(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte(`{"message":"payload too large"}`))
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want hosted size failure")
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Fatalf("state file error = %v, want not exist", err)
	}
}

func TestFlushAdvancesCursorPastOversizedMinimumBatch(t *testing.T) {
	store, dbPath := testStore(t)
	saveLargeTestDecision(t, store, "session-1", "toolu_1")

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want oversized minimum batch diagnostic")
	}
	if !strings.Contains(err.Error(), "advanced cursor past oversized minimum batch") {
		t.Fatalf("Flush() error = %q, want oversized skip diagnostic", err.Error())
	}
	if called {
		t.Fatal("server was called despite oversized local minimum batch")
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil || state.ActionID == "" {
		t.Fatalf("state = %+v, want cursor advanced", state)
	}
}

func TestFlushAdvancesCursorPastMinimumBatchWithWideReceiptRange(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var poisonActionID string
	if err := db.QueryRow(`
select id
from authorization_actions
order by updated_at_cursor_key, id
limit 1
	`).Scan(&poisonActionID); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxPayloadReceipts; i++ {
		if _, err := tx.Exec(`
insert into authorization_receipts(
  id, action_id, session_id, receipt_type, receipt_payload_json, receipt_hash, created_at
) values(?, 'act_foreign', 'session-foreign', 'observed', '{}', ?, ?)
		`, fmt.Sprintf("rcpt_foreign_%04d", i), fmt.Sprintf("hash_%04d", i), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`
insert into authorization_receipts(
  id, action_id, session_id, receipt_type, receipt_payload_json, receipt_hash, created_at
) values('rcpt_poison_tail', ?, 'session-1', 'observed', '{}', 'hash_poison_tail', ?)
	`, poisonActionID, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	called := false
	client := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	err = Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       "https://example.test",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     8,
		HTTPClient:     client,
	})
	if err == nil || !strings.Contains(err.Error(), "receipt range too large") {
		t.Fatalf("Flush() error = %v, want receipt range diagnostic", err)
	}
	if !errors.Is(err, sqlite.ErrLedgerReceiptRangeTooLarge) {
		t.Fatalf("Flush() error = %v, want ErrLedgerReceiptRangeTooLarge", err)
	}
	if called {
		t.Fatal("server was called despite wide receipt range")
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if state.UpdatedAfter == nil || state.ActionID != poisonActionID {
		t.Fatalf("state = %+v, want cursor advanced past %s", state, poisonActionID)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFlushPreservesHeartbeatStatePastOversizedMinimumBatch(t *testing.T) {
	store, dbPath := testStore(t)
	saveLargeTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	lastAttempt := time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339Nano)
	lastSuccess := time.Now().Add(-90 * time.Second).UTC().Format(time.RFC3339Nano)
	if err := SaveState(statePath, State{
		LastHeartbeatAttemptAt: lastAttempt,
		LastHeartbeatAt:        lastSuccess,
	}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     1,
		HTTPClient:     server.Client(),
	})
	if err == nil {
		t.Fatal("Flush() error = nil, want oversized minimum batch diagnostic")
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil || state.ActionID == "" {
		t.Fatalf("state = %+v, want cursor advanced", state)
	}
	if state.LastHeartbeatAttemptAt != lastAttempt || state.LastHeartbeatAt != lastSuccess {
		t.Fatalf("heartbeat state = %+v, want attempt %q success %q", state, lastAttempt, lastSuccess)
	}
}

func TestFlushDefaultsStatePathBesideLedgerDB(t *testing.T) {
	t.Setenv(envStatePath, "")
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	statePath := filepath.Join(filepath.Dir(dbPath), "stream-state.json")
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil {
		t.Fatal("updated_after was not persisted")
	}
}

func TestFlushUsesUpdatedAfterCursor(t *testing.T) {
	store, dbPath := testStore(t)
	saveTestDecision(t, store, "session-1", "toolu_1")

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	updatedAfter := time.Now().Add(time.Hour).UTC()
	if err := SaveState(statePath, State{
		UpdatedAfter:           &updatedAfter,
		LastHeartbeatAttemptAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       server.URL,
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		HTTPClient:     server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if called {
		t.Fatal("server was called despite cursor being newer than action")
	}
}

func TestFlushPostsHeartbeatWhenNoActionsArePending(t *testing.T) {
	_, dbPath := testStore(t)

	var got wireBatch
	server := capturePayloadServer(t, &got)
	t.Cleanup(server.Close)

	onFlushSuccessCalled := false
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:            dbPath,
		StatePath:         statePath,
		CloudURL:          server.URL,
		InstallationID:    "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:      "test-install-token",
		DeviceLabel:       "michel-macbook",
		HeartbeatInterval: time.Minute,
		HTTPClient:        server.Client(),
		OnFlushSuccess:    func() { onFlushSuccessCalled = true },
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	if got.BatchVersion != "v1" {
		t.Fatalf("batch_version = %q, want v1", got.BatchVersion)
	}
	if got.InstallationID != "ins_0123456789abcdefghijklmnopqrstuv" {
		t.Fatalf("installation_id = %q", got.InstallationID)
	}
	if got.Device == nil || got.Device.Label != "michel-macbook" {
		t.Fatalf("device = %+v", got.Device)
	}
	if len(got.Sessions) != 0 || len(got.Actions) != 0 || len(got.Receipts) != 0 {
		t.Fatalf("heartbeat counts = sessions %d actions %d receipts %d, want all zero", len(got.Sessions), len(got.Actions), len(got.Receipts))
	}
	if !onFlushSuccessCalled {
		t.Fatal("OnFlushSuccess was not called for accepted heartbeat")
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter != nil || state.ActionID != "" {
		t.Fatalf("state = %+v, want heartbeat not to advance ledger cursor", state)
	}
	if state.LastHeartbeatAttemptAt == "" || state.LastHeartbeatAt == "" {
		t.Fatalf("heartbeat state = %+v, want attempt and success persisted", state)
	}
}

func TestFlushSkipsHeartbeatBeforeInterval(t *testing.T) {
	_, dbPath := testStore(t)
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := SaveState(statePath, State{
		LastHeartbeatAttemptAt: time.Now().UTC().Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(server.Close)

	if err := Flush(context.Background(), Options{
		DBPath:            dbPath,
		StatePath:         statePath,
		CloudURL:          server.URL,
		InstallationID:    "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:      "test-install-token",
		HeartbeatInterval: time.Minute,
		HTTPClient:        server.Client(),
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	if called {
		t.Fatal("server was called before heartbeat interval elapsed")
	}
}

func TestFlushPersistsHeartbeatAttemptWhenHostedBackendFails(t *testing.T) {
	_, dbPath := testStore(t)

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	opts := Options{
		DBPath:            dbPath,
		StatePath:         statePath,
		CloudURL:          server.URL,
		InstallationID:    "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:      "test-install-token",
		HeartbeatInterval: time.Minute,
		HTTPClient:        server.Client(),
	}
	if err := Flush(context.Background(), opts); err == nil {
		t.Fatal("Flush() error = nil, want hosted failure")
	}
	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.LastHeartbeatAttemptAt == "" {
		t.Fatalf("state = %+v, want failed attempt persisted", state)
	}
	if state.LastHeartbeatAt != "" {
		t.Fatalf("state = %+v, want no successful heartbeat", state)
	}

	if err := Flush(context.Background(), opts); err != nil {
		t.Fatalf("second Flush() error = %v, want throttled no-op", err)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want failed heartbeat throttled", requests)
	}
}

func TestStatePersistsUpdatedAfterAsRFC3339String(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	updatedAfter := time.Date(2026, 6, 8, 12, 20, 7, 853885000, time.UTC)
	if err := SaveState(statePath, State{UpdatedAfter: &updatedAfter, ActionID: "act_123"}); err != nil {
		t.Fatalf("SaveState() error = %v", err)
	}

	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if got := string(raw); !strings.Contains(got, `"updated_after": "2026-06-08T12:20:07.853885Z"`) {
		t.Fatalf("state json = %s, want RFC3339 updated_after string", got)
	}

	state, err := LoadState(statePath)
	if err != nil {
		t.Fatalf("LoadState() error = %v", err)
	}
	if state.UpdatedAfter == nil || !state.UpdatedAfter.Equal(updatedAfter) || state.ActionID != "act_123" {
		t.Fatalf("LoadState() = %+v, want typed cursor", state)
	}
}

func TestParseStateUpdatedAfterAcceptsLegacyTimestampFormats(t *testing.T) {
	for _, value := range []string{
		"2026-06-08T12:20:07.853885",
		"2026-06-08 12:20:07.853885",
	} {
		parsed, err := parseStateUpdatedAfter(value)
		if err != nil {
			t.Fatalf("parseStateUpdatedAfter(%q) error = %v", value, err)
		}
		if got := parsed.UTC().Format(time.RFC3339Nano); got != "2026-06-08T12:20:07.853885Z" {
			t.Fatalf("parseStateUpdatedAfter(%q) = %q", value, got)
		}
	}
}

func testStore(t *testing.T) (*sqlite.Store, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "guard.db")
	store, err := sqlite.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, dbPath
}

// wireBatch decodes the clean-v1 envelope the flush posts for pages of
// post-cutover rows (the only kind a fresh test store produces).
type wireBatch struct {
	BatchVersion   string           `json:"batch_version"`
	BatchID        string           `json:"batch_id"`
	InstallationID string           `json:"installation_id"`
	SentAt         string           `json:"sent_at"`
	Device         *Device          `json:"device"`
	Sessions       []map[string]any `json:"sessions"`
	Actions        []map[string]any `json:"actions"`
	Receipts       []map[string]any `json:"receipts"`
}

func capturePayloadServer(t *testing.T, got *wireBatch) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultEndpoint {
			t.Fatalf("path = %q, want %q", r.URL.Path, DefaultEndpoint)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-install-token" {
			t.Fatalf("Authorization = %q, want bearer install token", got)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		// New agents must not send the legacy organization_id claim — the
		// install token alone binds the batch to its org.
		if strings.Contains(string(raw), `"organization_id"`) {
			t.Fatalf("payload contains organization_id claim: %s", raw)
		}
		if err := json.Unmarshal(raw, got); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
}

func saveTestDecision(t *testing.T, store *sqlite.Store, sessionID, toolUseID string) {
	t.Helper()
	_, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     sessionID,
		Agent:         "claude",
		CWD:           "/tmp/project",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     toolUseID,
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		ReasonCode: "OBSERVE_MODE",
		Reason:     "Allowed in observe mode",
		RiskEvent: risk.RiskEvent{
			Operation:      "read",
			OperationClass: "read",
			ResourceClass:  "file",
		},
	})
	if err != nil {
		t.Fatalf("SaveDecision() error = %v", err)
	}
}

func saveLargeTestDecision(t *testing.T, store *sqlite.Store, sessionID, toolUseID string) {
	t.Helper()
	_, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     sessionID,
		Agent:         "claude",
		CWD:           "/tmp/project",
		HookEventName: "PreToolUse",
		ToolName:      "Write",
		ToolUseID:     toolUseID,
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		ReasonCode: "OBSERVE_MODE",
		Reason:     "Allowed in observe mode",
		RiskEvent: risk.RiskEvent{
			Operation:      "write",
			OperationClass: "write",
			ResourceClass:  "file",
			CommandSummary: strings.Repeat("x", MaxPayloadBytes),
		},
	})
	if err != nil {
		t.Fatalf("SaveDecision() error = %v", err)
	}
}

func TestFlushRestoresBatchLimitAfterReduction(t *testing.T) {
	store, dbPath := testStore(t)
	for i := 0; i < 25; i++ {
		saveTestDecision(t, store, "session-1", fmt.Sprintf("toolu_%02d", i))
	}

	var batchSizes []int
	requests := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests++
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		var payload wireBatch
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatal(err)
		}
		if requests == 1 {
			return &http.Response{StatusCode: http.StatusRequestEntityTooLarge, Body: io.NopCloser(strings.NewReader(""))}, nil
		}
		batchSizes = append(batchSizes, len(payload.Actions))
		return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}

	statePath := filepath.Join(t.TempDir(), "stream-state.json")
	if err := Flush(context.Background(), Options{
		DBPath:         dbPath,
		StatePath:      statePath,
		CloudURL:       "https://example.test",
		InstallationID: "ins_0123456789abcdefghijklmnopqrstuv",
		InstallToken:   "test-install-token",
		BatchLimit:     8,
		HTTPClient:     client,
	}); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	// The first post is rejected with 413 → the page limit halves to 4; each
	// accepted post then increments it by one toward the cap. Payload action counts
	// exceed the page size (the receipt rowid range pulls in neighbors), so
	// assert recovery via the essential property: without it every remaining
	// page stays at 4 and no accepted payload ever reaches the original cap.
	maxSize := 0
	for _, size := range batchSizes {
		maxSize = max(maxSize, size)
	}
	if maxSize < 8 {
		t.Fatalf("accepted batch sizes = %v, want at least one >= 8 (limit recovered)", batchSizes)
	}
}
