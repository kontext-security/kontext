package server

import (
	"context"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
)

// A deferred-recording server must settle the hook response without touching
// the store: the response carries a pre-minted action ID, and the persistence
// job — run later, on the executor's schedule — writes the row under that
// same ID.
func TestDeferRecordAnswersWithoutPersisting(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var jobs []func(context.Context) error
	server, err := NewServerWithPolicyAndOptions(store, nil, Options{
		DeferRecord: func(job func(context.Context) error) {
			jobs = append(jobs, job)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	event := risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "echo hi"},
	}
	decision, err := server.ProcessHookEvent(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if decision.EventID == "" || !strings.HasPrefix(decision.EventID, "act_") {
		t.Fatalf("EventID = %q, want pre-minted act_ id", decision.EventID)
	}
	if len(jobs) != 1 {
		t.Fatalf("deferred jobs = %d, want 1", len(jobs))
	}

	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 0 {
		t.Fatalf("actions before job ran = %d, want 0 (response must not wait on the store)", summary.Actions)
	}
	sessions, err := store.Sessions(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Fatalf("sessions before job ran = %d, want 0 (session upsert must not wait on the store either)", len(sessions))
	}

	if err := jobs[0](context.Background()); err != nil {
		t.Fatalf("deferred job error = %v", err)
	}

	events, err := store.Events(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range events {
		if record.ID == decision.EventID {
			found = true
		}
	}
	if !found {
		t.Fatalf("no persisted decision with the response's EventID %q; got %d events", decision.EventID, len(events))
	}
	session, err := store.Session(context.Background(), "s1")
	if err != nil {
		t.Fatalf("session after job ran: %v", err)
	}
	if session.Status != "open" {
		t.Fatalf("session status = %q, want open (deferred job must run the full session upsert)", session.Status)
	}
}

// Non-blocking hooks must not defer: their response never waits on the store
// (async ingest answers them before ingestion), so deferring their writes
// would only nest one background hop inside another and reorder rows for no
// latency win.
func TestDeferRecordSkipsNonBlockingHooks(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var jobs []func(context.Context) error
	server, err := NewServerWithPolicyAndOptions(store, nil, Options{
		DeferRecord: func(job func(context.Context) error) {
			jobs = append(jobs, job)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	event := risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PostToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "echo hi"},
	}
	if _, err := server.ProcessHookEvent(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 0 {
		t.Fatalf("deferred jobs = %d, want 0 (non-blocking hooks stay synchronous)", len(jobs))
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 1 {
		t.Fatalf("actions = %d, want 1 persisted synchronously for the non-blocking hook", summary.Actions)
	}
	if _, err := store.Session(context.Background(), "s1"); err != nil {
		t.Fatalf("session after synchronous ingest: %v", err)
	}
}

// A deferred record can land after a SessionEnd already closed its session:
// the job waits on classifier inference and a possibly cold store while the
// session winds down in order. Late bookkeeping must not undo that close.
func TestDeferredRecordDoesNotReopenClosedSession(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var jobs []func(context.Context) error
	server, err := NewServerWithPolicyAndOptions(store, nil, Options{
		DeferRecord: func(job func(context.Context) error) {
			jobs = append(jobs, job)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	event := risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "echo hi"},
	}
	decision, err := server.ProcessHookEvent(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("deferred jobs = %d, want 1", len(jobs))
	}

	// The session ends in causal order while the deferred job is still
	// pending: SessionEnd ingests synchronously (creating the row), then the
	// runtime closes the session, exactly as the socket service does.
	if _, err := server.ProcessHookEvent(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "SessionEnd",
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.CloseSession(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}

	if err := jobs[0](context.Background()); err != nil {
		t.Fatalf("deferred job error = %v", err)
	}

	session, err := store.Session(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if session.Status != "closed" {
		t.Fatalf("session status after late deferred write = %q, want closed", session.Status)
	}
	events, err := store.Events(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range events {
		if record.ID == decision.EventID {
			found = true
		}
	}
	if !found {
		t.Fatalf("late deferred job must still persist the decision %q", decision.EventID)
	}
}

// An event with no session ID must land under the store's catch-all session
// on the deferred path exactly as it does on the synchronous one: the
// normalization happens before the response, the upsert after.
func TestDeferRecordNormalizesEmptySessionID(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var jobs []func(context.Context) error
	server, err := NewServerWithPolicyAndOptions(store, nil, Options{
		DeferRecord: func(job func(context.Context) error) {
			jobs = append(jobs, job)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	event := risk.HookEvent{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "echo hi"},
	}
	decision, err := server.ProcessHookEvent(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if len(jobs) != 1 {
		t.Fatalf("deferred jobs = %d, want 1", len(jobs))
	}
	if err := jobs[0](context.Background()); err != nil {
		t.Fatalf("deferred job error = %v", err)
	}

	events, err := store.Events(context.Background(), sqlite.NormalizeSessionID(""))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range events {
		if record.ID == decision.EventID {
			found = true
		}
	}
	if !found {
		t.Fatalf("no decision under the catch-all session with EventID %q; got %d events", decision.EventID, len(events))
	}
}

// Without a DeferRecord executor the historical behavior holds: the response
// waits on the write and carries the persisted row's ID.
func TestNilDeferRecordStaysSynchronous(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	server := newTestServer(t, store)

	event := risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]any{"command": "echo hi"},
	}
	decision, err := server.ProcessHookEvent(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Actions != 1 {
		t.Fatalf("actions = %d, want 1 persisted synchronously", summary.Actions)
	}
	if decision.EventID == "" {
		t.Fatal("EventID empty on synchronous path")
	}
}
