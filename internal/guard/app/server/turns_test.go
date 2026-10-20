package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

func confirmedCapture(mode payloadcapture.Mode, workType bool) payloadcapture.RuntimeConfiguration {
	return payloadcapture.SafeRuntimeConfiguration(payloadcapture.RuntimeConfiguration{
		ConfiguredMode: mode, EffectiveMode: mode, ConfigIdentity: strings.Repeat("c", 64), Confirmed: true,
		WorkTypeClassification: workType,
	})
}

func TestTurnSourceAndPromptMode(t *testing.T) {
	yes := true
	for _, test := range []struct {
		prompt    string
		interrupt *bool
		want      string
	}{
		{"fix the failing spec", nil, sqlite.TurnSourceUserPrompt},
		{"/review the diff", nil, sqlite.TurnSourceSlashCommand},
		{" /not a command", nil, sqlite.TurnSourceUserPrompt},
		{"/review", &yes, sqlite.TurnSourceInterrupt},
	} {
		if got := turnSource(test.prompt, test.interrupt); got != test.want {
			t.Errorf("turnSource(%q) = %q, want %q", test.prompt, got, test.want)
		}
	}

	prompt := "fix the failing cost summary spec"
	paste := strings.Repeat("x", 2<<20)
	for _, test := range []struct {
		name    string
		capture payloadcapture.RuntimeConfiguration
		prompt  string
		mode    string
		limit   int
	}{
		{name: "no confirmed directive", capture: payloadcapture.DefaultRuntimeConfiguration(), prompt: prompt, mode: sqlite.TurnPromptSkipped},
		{name: "unconfirmed switch on", capture: payloadcapture.SafeRuntimeConfiguration(payloadcapture.RuntimeConfiguration{EffectiveMode: payloadcapture.ModeFull, WorkTypeClassification: true}), prompt: prompt, mode: sqlite.TurnPromptSkipped},
		{name: "omitted, switch on", capture: confirmedCapture(payloadcapture.ModeOmitted, true), prompt: prompt, mode: sqlite.TurnPromptOmitted},
		{name: "omitted, switch off", capture: confirmedCapture(payloadcapture.ModeOmitted, false), prompt: prompt, mode: sqlite.TurnPromptOmitted},
		{name: "summaries, switch off", capture: confirmedCapture(payloadcapture.ModeSummary, false), prompt: prompt, mode: sqlite.TurnPromptSkipped},
		{name: "full, switch off", capture: confirmedCapture(payloadcapture.ModeFull, false), prompt: prompt, mode: sqlite.TurnPromptSkipped},
		{name: "summaries, switch on", capture: confirmedCapture(payloadcapture.ModeSummary, true), prompt: prompt, mode: sqlite.TurnPromptExcerpt, limit: 4_000},
		{name: "full, switch on", capture: confirmedCapture(payloadcapture.ModeFull, true), prompt: prompt, mode: sqlite.TurnPromptExcerpt, limit: 64_000},
		{name: "2 MB paste", capture: confirmedCapture(payloadcapture.ModeFull, true), prompt: paste, mode: sqlite.TurnPromptSkipped},
		{name: "2 MB paste, omitted", capture: confirmedCapture(payloadcapture.ModeOmitted, true), prompt: paste, mode: sqlite.TurnPromptOmitted},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := turnPrompt(test.prompt, test.capture)
			if got.Mode != test.mode || got.Chars != int64(utf8.RuneCountInString(test.prompt)) {
				t.Fatalf("prompt = %+v, want mode %s with true chars", got, test.mode)
			}
			if (got.Text != nil) != (test.mode == sqlite.TurnPromptExcerpt) || (got.SHA256 != nil) != (test.mode == sqlite.TurnPromptExcerpt) {
				t.Fatalf("text and hash travel only with an excerpt: %+v", got)
			}
			if test.limit > 0 && len(*got.Text) > test.limit {
				t.Fatalf("excerpt %d bytes over %d", len(*got.Text), test.limit)
			}
		})
	}
}

func TestTurnPromptExcerpt(t *testing.T) {
	summaries := confirmedCapture(payloadcapture.ModeSummary, true)
	full := confirmedCapture(payloadcapture.ModeFull, true)
	secret := "sk-proj-" + strings.Repeat("A1b2", 8)
	prompt := "<system-reminder>\nThe user opened report.md\n</system-reminder>\nfix   the\tfailing\n\nspec, the key is " + secret +
		" <pasted_content id=\"1\">\nhuge log\n</pasted_content> and <command-message>review is running</command-message>done\x00now"
	got := turnPrompt(prompt, summaries)
	if *got.Text != "fix the failing spec, the key is "+payloadcapture.RedactedPlaceholder+" and done now" || *got.Truncated {
		t.Fatalf("excerpt = %q (truncated %v)", *got.Text, *got.Truncated)
	}
	if got.Chars != int64(utf8.RuneCountInString(prompt)) {
		t.Fatalf("chars = %d, want the original's runes", got.Chars)
	}
	// The hash is over the trimmed, collapsed original, so spacing alone
	// does not change it, and the excerpt's stripping does not either.
	digest := sha256.Sum256([]byte("Continue"))
	for _, variant := range []string{"Continue", " Continue \n", "Continue\t"} {
		if hash := *turnPrompt(variant, summaries).SHA256; hash != hex.EncodeToString(digest[:]) {
			t.Errorf("sha256(%q) = %s", variant, hash)
		}
	}

	long := strings.Repeat("word ", 20_000) + "the end"
	for capture, limit := range map[*payloadcapture.RuntimeConfiguration]int{&summaries: 4_000, &full: 64_000} {
		got := turnPrompt(long, *capture)
		if !*got.Truncated || len(*got.Text) > limit || !strings.Contains(*got.Text, "[Context omitted]") || !strings.HasSuffix(*got.Text, "the end") {
			t.Fatalf("bounded excerpt: %d bytes, truncated %v", len(*got.Text), *got.Truncated)
		}
	}
	// A secret across the bound leaves no prefix: redaction runs first.
	crossing := strings.Repeat("a ", 999) + secret + strings.Repeat(" b", 2_000)
	if text := *turnPrompt(crossing, summaries).Text; strings.Contains(text, "sk-proj-") || strings.Contains(text, "A1b2A1b2") {
		t.Fatalf("secret prefix survived bounding: %q", text)
	}
}

type turnHarness struct {
	t      *testing.T
	store  *sqlite.Store
	server *Server
	jobs   []func(context.Context) error
}

func newTurnHarness(t *testing.T, store *sqlite.Store) *turnHarness {
	t.Helper()
	h := &turnHarness{t: t, store: store}
	server, err := NewServerWithPolicyAndOptions(store, nil, Options{
		DeferRecord: func(job func(context.Context) error) error {
			h.jobs = append(h.jobs, job)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.server = server
	return h
}

func (h *turnHarness) hook(event risk.HookEvent) {
	h.t.Helper()
	if event.Agent == "" {
		event.Agent = "claude"
	}
	if _, err := h.server.ProcessHookEvent(context.Background(), event); err != nil {
		h.t.Fatal(err)
	}
}

func (h *turnHarness) runJobs() {
	h.t.Helper()
	for _, job := range h.jobs {
		if err := job(context.Background()); err != nil {
			h.t.Fatal(err)
		}
	}
	h.jobs = nil
}

func prompt(session, text string) risk.HookEvent {
	return risk.HookEvent{SessionID: session, HookEventName: "UserPromptSubmit", ToolInput: map[string]any{"prompt": text}}
}

func toolUse(session, id string) risk.HookEvent {
	return risk.HookEvent{SessionID: session, HookEventName: "PreToolUse", ToolName: "Bash", ToolUseID: id, ToolInput: map[string]any{"command": "printf ok"}}
}

// actionTurns returns each action's turn by hook and tool-use id.
func actionTurns(t *testing.T, store *sqlite.Store) map[string][]string {
	t.Helper()
	actions, err := store.AuthorizationActions(context.Background(), sqlite.LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	turns := map[string][]string{}
	for _, action := range actions {
		key, _ := action["adapter_event_name"].(string)
		if id, _ := action["tool_use_id"].(string); id != "" {
			key += ":" + id
		}
		turn, _ := action["turn_id"].(string)
		turns[key] = append(turns[key], turn)
	}
	return turns
}

func TestRuntimeMintsTurnsAndStampsActions(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.SetPayloadCaptureConfiguration(confirmedCapture(payloadcapture.ModeSummary, true))
	h := newTurnHarness(t, store)

	// The prompt's PreToolUse arrives before the prompt's deferred write ran,
	// and still carries the turn: minting is synchronous and memory-only.
	h.hook(prompt("s", "run printf once"))
	h.hook(toolUse("s", "t1"))
	if pending, err := store.PendingTurns(ctx, 10); err != nil || len(pending) != 0 {
		t.Fatalf("turn written on the hook path: %+v, %v", pending, err)
	}
	h.runJobs()
	h.hook(risk.HookEvent{SessionID: "s", HookEventName: "PostToolUse", ToolName: "Bash", ToolUseID: "t1"})

	// The workspace flips capture mode mid-session: the next turn snapshots
	// the new directive, the first keeps its own.
	store.SetPayloadCaptureConfiguration(confirmedCapture(payloadcapture.ModeOmitted, true))
	h.hook(prompt("s", "now explain what the output means"))
	h.hook(toolUse("s", "t2"))
	h.runJobs()

	turns, err := store.PendingTurns(ctx, 10)
	if err != nil || len(turns) != 2 {
		t.Fatalf("turns = %+v, %v", turns, err)
	}
	first, second := turns[0], turns[1]
	if first.Sequence != 1 || second.Sequence != 2 || first.ID == second.ID || !strings.HasPrefix(first.ID, "turn_") || len(first.ID) != len("turn_")+36 {
		t.Fatalf("turn identity: %+v / %+v", first, second)
	}
	if first.Prompt.Mode != sqlite.TurnPromptExcerpt || *first.Prompt.Text != "run printf once" || second.Prompt.Mode != sqlite.TurnPromptOmitted || second.Prompt.Text != nil {
		t.Fatalf("prompt modes: %+v / %+v", first.Prompt, second.Prompt)
	}
	if first.Agent != "claude" || first.Source != sqlite.TurnSourceUserPrompt || first.SessionID != "s" {
		t.Fatalf("turn fields: %+v", first)
	}
	got := actionTurns(t, store)
	for key, want := range map[string]string{
		"UserPromptSubmit": first.ID, // the prompt event's own row
		"PreToolUse:t1":    first.ID,
		"PostToolUse:t1":   first.ID,
		"PreToolUse:t2":    second.ID,
	} {
		rows := got[key]
		if key == "UserPromptSubmit" {
			rows = rows[:1]
		}
		if len(rows) == 0 {
			t.Fatalf("no %s action: %v", key, got)
		}
		for _, turn := range rows {
			if turn != want {
				t.Errorf("%s turn = %q, want %q (all: %v)", key, turn, want, got)
			}
		}
	}

	// The turn id is annotation, not part of the signed receipt.
	receipts, err := store.AuthorizationReceipts(ctx, sqlite.LedgerExportOptions{})
	if err != nil || len(receipts) == 0 {
		t.Fatalf("receipts: %d, %v", len(receipts), err)
	}
	for _, receipt := range receipts {
		if payload, _ := receipt["receipt_payload_json"].(string); strings.Contains(payload, "turn_") {
			t.Fatalf("receipt payload carries the turn: %s", payload)
		}
	}

	// A daemon restart between prompts: the new runtime has no cache and
	// resolves the turn from SQLite inside the deferred job.
	restarted := newTurnHarness(t, store)
	restarted.hook(toolUse("s", "t3"))
	restarted.runJobs()
	if got := actionTurns(t, store)["PreToolUse:t3"]; len(got) == 0 || got[0] != second.ID || got[len(got)-1] != second.ID {
		t.Fatalf("after restart t3 turn = %v, want %s", got, second.ID)
	}
	// SessionEnd is the turn's last action.
	restarted.hook(risk.HookEvent{SessionID: "s", HookEventName: "SessionEnd"})
	if got := actionTurns(t, store)["SessionEnd"]; len(got) != 1 || got[0] != second.ID {
		t.Fatalf("SessionEnd turn = %v", got)
	}
}

// SessionEnd drops the session's cached turn; the next event of a resumed
// session resolves it from SQLite again.
func TestSessionEndForgetsTheCachedTurn(t *testing.T) {
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	runtime := newGuardHookRuntime(store, nil, "", "", nil, nil, nil)
	minted, mint, _ := runtime.trackTurn(risk.HookEvent{SessionID: "s", Agent: "claude", HookEventName: "UserPromptSubmit", ToolInput: map[string]any{"prompt": "hi"}})
	if mint == nil || minted.TurnID == "" {
		t.Fatal("prompt minted no turn")
	}
	ended, _, unresolved := runtime.trackTurn(risk.HookEvent{SessionID: "s", Agent: "claude", HookEventName: "SessionEnd"})
	if ended.TurnID != minted.TurnID || unresolved {
		t.Fatalf("SessionEnd turn = %q (unresolved %v), want %q", ended.TurnID, unresolved, minted.TurnID)
	}
	if _, known := runtime.turns.lookup("s"); known {
		t.Fatal("SessionEnd kept the cached turn")
	}
	if _, _, unresolved := runtime.trackTurn(toolUse("s", "t1")); !unresolved {
		t.Fatal("an event after SessionEnd did not resolve from the store")
	}
	if err := runtime.CloseSession(context.Background(), "s"); err != nil {
		t.Fatal(err)
	}
}

// A daemon restart after the prompt hook answered but before its deferred
// write ran loses that turn. Nothing fails: the prompt's usage stays
// unmatched, and the turn's actions resolve to the session's last stored
// turn, the only one SQLite knows.
func TestRestartBeforeDeferredTurnWrite(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := newTurnHarness(t, store)
	h.hook(prompt("s", "first"))
	h.runJobs()
	h.hook(prompt("s", "second, lost with its job"))
	h.jobs = nil

	restarted := newTurnHarness(t, store)
	restarted.hook(toolUse("s", "t1"))
	restarted.runJobs()
	turns, err := store.PendingTurns(ctx, 10)
	if err != nil || len(turns) != 1 {
		t.Fatalf("turns = %+v, %v", turns, err)
	}
	if got := actionTurns(t, store)["PreToolUse:t1"]; len(got) == 0 || got[0] != turns[0].ID {
		t.Fatalf("t1 turn = %v, want %s", got, turns[0].ID)
	}
	// The next prompt still takes the next free sequence.
	restarted.hook(prompt("s", "third"))
	restarted.runJobs()
	if turns, err := store.PendingTurns(ctx, 10); err != nil || len(turns) != 2 || turns[1].Sequence != 2 {
		t.Fatalf("turns after the restart = %+v, %v", turns, err)
	}
}

func TestPromptsThatMintNoTurn(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.OpenStore(t.TempDir() + "/guard.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h := newTurnHarness(t, store)
	h.hook(prompt("s", ""))
	h.hook(risk.HookEvent{SessionID: "s", Agent: "cursor", HookEventName: "UserPromptSubmit", ToolInput: map[string]any{"prompt": "hi"}})
	h.hook(toolUse("s", "t1"))
	h.runJobs()
	if turns, err := store.PendingTurns(ctx, 10); err != nil || len(turns) != 0 {
		t.Fatalf("turns = %+v, %v", turns, err)
	}
	for key, turns := range actionTurns(t, store) {
		for _, turn := range turns {
			if turn != "" {
				t.Fatalf("%s carries turn %q without a minted turn", key, turn)
			}
		}
	}
	// Codex sessions mint under their prefixed id, like their usage.
	h.hook(risk.HookEvent{SessionID: "codex-th", Agent: "codex", HookEventName: "UserPromptSubmit", ToolInput: map[string]any{"prompt": "hi"}})
	h.runJobs()
	if turns, err := store.PendingTurns(ctx, 10); err != nil || len(turns) != 1 || turns[0].SessionID != "codex-th" || turns[0].Agent != "codex" {
		t.Fatalf("codex turns = %+v, %v", turns, err)
	}
}
