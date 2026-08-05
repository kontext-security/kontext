package server

import (
	"context"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
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
