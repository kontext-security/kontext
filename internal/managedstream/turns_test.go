package managedstream

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/modelusage"
)

func saveTestTurns(t *testing.T, store *sqlite.Store, sessions ...string) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	for i, session := range sessions {
		if _, err := store.EnsureObservedSessionWithMode(ctx, session, "claude", "/tmp", "observe"); err != nil {
			t.Fatal(err)
		}
		prompt := sqlite.SizeOnlyTurnPrompt(sqlite.TurnPromptSkipped, 4)
		if i == 0 {
			prompt = sqlite.ExcerptTurnPrompt("fix <the> spec & ship", 21, false, strings.Repeat("a", 64))
		}
		if err := store.SaveTurn(ctx, sqlite.TurnRecord{Schema: sqlite.TurnSchemaVersion, ID: "turn_" + session, SessionID: session,
			Agent: "claude", StartedAt: sqlite.FormatTurnTime(base.Add(time.Duration(i) * time.Second)), Source: sqlite.TurnSourceUserPrompt, Prompt: prompt}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTurnUploadRetriesAndAcknowledges(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "guard.db")
	store, err := sqlite.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	saveTestTurns(t, store, "s1", "s2")
	// An unrelated session without turns must not ride along.
	if _, err := store.EnsureObservedSessionWithMode(ctx, "idle", "claude", "/tmp", "observe"); err != nil {
		t.Fatal(err)
	}
	reject := true
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts++
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		// Excerpts travel without HTML escaping.
		if !strings.Contains(string(body), `"text":"fix <the> spec & ship"`) {
			t.Errorf("excerpt encoding: %s", body)
		}
		var p Payload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Error(err)
		}
		var sessions []string
		for _, session := range p.Sessions {
			sessions = append(sessions, session["id"].(string))
		}
		if len(p.Turns) != 2 || len(p.Actions) != 0 || len(p.ToolUsage) != 0 || strings.Join(sessions, ",") != "s1,s2" {
			t.Errorf("unexpected turn batch: sessions %v, %+v", sessions, p.Turns)
		}
		if p.Turns[0].Schema != "turn/v1" || p.Turns[0].Prompt.Mode != "excerpt" || p.Turns[1].Prompt.Text != nil || p.Turns[0].Sequence != 1 {
			t.Errorf("turn shape: %+v", p.Turns)
		}
		if reject {
			w.WriteHeader(503)
			return
		}
		// The server quarantines one; both are answered for.
		_, _ = w.Write([]byte(`{"quarantined":[{"kind":"turn","id":"turn_s2"}],"altered":[]}`))
	}))
	defer server.Close()
	opts := Options{DBPath: path, CloudURL: server.URL, InstallationID: "ins_test", InstallToken: "test"}
	if err := flushTurns(ctx, opts); err == nil {
		t.Fatal("expected upload failure")
	}
	if pending, err := store.PendingTurns(ctx, 10); err != nil || len(pending) != 2 {
		t.Fatalf("a failed upload acknowledged turns: %+v, %v", pending, err)
	}
	reject = false
	if err := flushTurns(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if err := flushTurns(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if posts != 2 {
		t.Fatalf("posts=%d, want failed + successful retry", posts)
	}
	if pending, err := store.PendingTurns(ctx, 10); err != nil || len(pending) != 0 {
		t.Fatalf("pending after ack: %+v, %v", pending, err)
	}
}

// A batch over the body limit is halved until it fits.
func TestTurnUploadHalvesOversizedBatches(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "guard.db")
	store, err := sqlite.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.EnsureObservedSessionWithMode(ctx, "s", "claude", "/tmp", "observe"); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	for i := range 6 {
		// Full-capture excerpts at the 64,000-byte bound.
		text := strings.Repeat("\"", 32_000)
		if err := store.SaveTurn(ctx, sqlite.TurnRecord{ID: "turn_" + string(rune('a'+i)), SessionID: "s", Agent: "claude",
			StartedAt: sqlite.FormatTurnTime(base.Add(time.Duration(i) * time.Second)), Source: sqlite.TurnSourceUserPrompt,
			Prompt: sqlite.ExcerptTurnPrompt(text+text, 64_000, true, strings.Repeat("a", 64))}); err != nil {
			t.Fatal(err)
		}
	}
	var batches []int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if len(body) > MaxPayloadBytes {
			t.Errorf("body %d bytes over the limit", len(body))
		}
		var p Payload
		if err := json.Unmarshal(body, &p); err != nil {
			t.Error(err)
		}
		batches = append(batches, len(p.Turns))
	}))
	defer server.Close()
	if err := flushTurns(ctx, Options{DBPath: path, CloudURL: server.URL, InstallationID: "ins_test", InstallToken: "test"}); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range batches {
		total += n
	}
	if total != 6 || len(batches) < 3 {
		t.Fatalf("batches = %v", batches)
	}
}

// Flush sends a session's turns before the usage that references them.
func TestFlushSendsTurnsBeforeToolUsage(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "guard.db")
	store, err := sqlite.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	saveTestTurns(t, store, "s")
	records, err := modelusage.ReadClaudeTranscript(strings.NewReader(`{"type":"assistant","sessionId":"s","timestamp":"2026-10-19T10:00:01Z","message":{"id":"a","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Bash"}],"usage":{"output_tokens":3}}}` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	records[0].TurnID = "turn_s"
	if err := store.SaveToolUsage(ctx, "claude", records[0]); err != nil {
		t.Fatal(err)
	}
	var order []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		switch {
		case len(p.Turns) > 0:
			order = append(order, "turns")
		case len(p.ToolUsage) > 0:
			order = append(order, "tool_usage")
		case len(p.Actions) > 0:
			order = append(order, "ledger")
		}
	}))
	defer server.Close()
	if err := Flush(ctx, Options{DBPath: path, CloudURL: server.URL, InstallationID: "ins_test", InstallToken: "test", StatePath: filepath.Join(t.TempDir(), "state.json")}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "turns,tool_usage" {
		t.Fatalf("posts = %v", order)
	}
}

// The hosted ledger refuses a whole batch over a turn whose session is not in
// it or names another agent. Such a turn takes its session's agent, or is
// dropped when it has no exportable session, so it cannot block the outbox.
func TestTurnUploadKeepsBatchesAcceptable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "guard.db")
	store, err := sqlite.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.EnsureObservedSessionWithMode(ctx, "codex-th", "codex", "/tmp", "observe"); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 10, 19, 10, 0, 0, 0, time.UTC)
	for i, turn := range []struct{ id, session string }{{"turn_orphan", "missing"}, {"turn_codex", "codex-th"}} {
		if err := store.SaveTurn(ctx, sqlite.TurnRecord{ID: turn.id, SessionID: turn.session, Agent: "claude",
			StartedAt: sqlite.FormatTurnTime(base.Add(time.Duration(i) * time.Second)), Source: sqlite.TurnSourceUserPrompt,
			Prompt: sqlite.SizeOnlyTurnPrompt(sqlite.TurnPromptSkipped, 1)}); err != nil {
			t.Fatal(err)
		}
	}
	var sent []sqlite.TurnRecord
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		sent = append(sent, p.Turns...)
	}))
	defer server.Close()
	if err := flushTurns(ctx, Options{DBPath: path, CloudURL: server.URL, InstallationID: "ins_test", InstallToken: "test"}); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0].ID != "turn_codex" || sent[0].Agent != "codex" {
		t.Fatalf("sent = %+v", sent)
	}
	if pending, err := store.PendingTurns(ctx, 10); err != nil || len(pending) != 0 {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
}

// A failed turn upload, such as an API that predates turns, does not hold
// back tool usage.
func TestFlushUploadsUsageWhenTurnsFail(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "guard.db")
	store, err := sqlite.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	saveTestTurns(t, store, "s")
	records, err := modelusage.ReadClaudeTranscript(strings.NewReader(`{"type":"assistant","sessionId":"s","timestamp":"2026-10-19T10:00:01Z","message":{"id":"a","model":"claude-fable-5-1","content":[{"type":"tool_use","id":"t","name":"Bash"}],"usage":{"output_tokens":3}}}` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveToolUsage(ctx, "claude", records[0]); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p Payload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			t.Error(err)
		}
		if len(p.Turns) > 0 {
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()
	if err := Flush(ctx, Options{DBPath: path, CloudURL: server.URL, InstallationID: "ins_test", InstallToken: "test", StatePath: filepath.Join(t.TempDir(), "state.json")}); err == nil {
		t.Fatal("expected the turn failure to be reported")
	}
	if usage, err := store.PendingToolUsage(ctx, 10); err != nil || len(usage) != 0 {
		t.Fatalf("usage held back by a turn failure: %+v, %v", usage, err)
	}
	if turns, err := store.PendingTurns(ctx, 10); err != nil || len(turns) != 1 {
		t.Fatalf("failed turns acknowledged: %+v, %v", turns, err)
	}
}
