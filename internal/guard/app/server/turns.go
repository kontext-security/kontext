package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/kontext-security/kontext/internal/guard/risk"
	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/modelusage"
	"github.com/kontext-security/kontext/internal/payloadcapture"
)

const (
	// maxTurnPromptBytes is the hook-metadata redaction guard: a longer prompt
	// is not redacted at all and its turn carries its size only.
	maxTurnPromptBytes = 1 << 20
	// The excerpt bounds, in bytes, which keeps them within the wire's
	// character bounds. Under Summaries the classifier reads only this much;
	// under Full payloads it is the captured-payload cap.
	summaryTurnExcerptBytes = 4_000
	fullTurnExcerptBytes    = 64_000
	// maxTrackedTurnSessions bounds the cache; dropped sessions are rebuilt
	// from SQLite on their next event.
	maxTrackedTurnSessions = 4096
)

// turnTracker remembers each session's current turn id, so an event finds
// its turn without touching the store on the hook path. SQLite holds the
// turns; an unknown session is resolved from it off the hook path.
type turnTracker struct {
	mu      sync.Mutex
	current map[string]string // session → turn id; "" means none
}

func newTurnTracker() *turnTracker {
	return &turnTracker{current: map[string]string{}}
}

// mint starts a new turn for the session and returns its id.
func (t *turnTracker) mint(session string) string {
	id := "turn_" + uuid.NewString()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.current) >= maxTrackedTurnSessions {
		clear(t.current)
	}
	t.current[session] = id
	return id
}

func (t *turnTracker) lookup(session string) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	id, ok := t.current[session]
	return id, ok
}

// fill caches a turn resolved from the store unless a newer mint got there
// first.
func (t *turnTracker) fill(session, id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.current[session]; !ok && len(t.current) < maxTrackedTurnSessions {
		t.current[session] = id
	}
}

func (t *turnTracker) forget(session string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.current, session)
}

// mintedTurn is a turn minted on the hook path, persisted with the prompt
// event's own record.
type mintedTurn struct {
	record  sqlite.TurnRecord
	prompt  string
	capture payloadcapture.RuntimeConfiguration
}

// trackTurn stamps the event with its session's current turn, minting a new
// one for a non-empty prompt. It touches memory only. unresolved reports a
// session whose turn must be looked up in the store before the event is
// recorded (after a restart, or once the cache dropped it).
func (r guardHookRuntime) trackTurn(event risk.HookEvent) (stamped risk.HookEvent, minted *mintedTurn, unresolved bool) {
	if r.turns == nil {
		return event, nil, false
	}
	session := sqlite.NormalizeSessionID(event.SessionID)
	prompt, _ := event.ToolInput["prompt"].(string)
	// A harness message (a task notification, a session event) arrives as a
	// prompt but starts no turn: the work after it stays with the person's
	// prompt before, and nothing is classified for it.
	if agent := turnAgent(event.Agent); event.HookEventName == hook.HookUserPromptSubmit.String() && !modelusage.IsHarnessEnvelope(prompt) && agent != "" {
		event.TurnID = r.turns.mint(session)
		return event, &mintedTurn{
			record: sqlite.TurnRecord{
				Schema:    sqlite.TurnSchemaVersion,
				ID:        event.TurnID,
				SessionID: session,
				Agent:     agent,
				StartedAt: sqlite.FormatTurnTime(event.Timestamp),
				Source:    turnSource(prompt, event.IsInterrupt),
			},
			prompt: prompt,
			// Each turn keeps the capture directive in force when it was
			// minted, as each decision does.
			capture: r.store.PayloadCaptureConfiguration(),
		}, false
	}
	id, known := r.turns.lookup(session)
	if event.HookEventName == hook.HookSessionEnd.String() {
		r.turns.forget(session)
	}
	event.TurnID = id
	return event, nil, !known
}

// recordTurn persists a minted turn, or resolves an unresolved one, before
// the event's own record is written, so that record carries the turn id. A
// failure costs the turn, never the decision record.
func (r guardHookRuntime) recordTurn(ctx context.Context, event *risk.HookEvent, minted *mintedTurn, unresolved bool) {
	switch {
	case minted != nil:
		record := minted.record
		record.Prompt = turnPrompt(minted.prompt, minted.capture)
		if err := r.store.SaveTurn(ctx, record); err != nil {
			log.Printf("record turn %s: %v", record.ID, err)
		}
	case unresolved:
		session := sqlite.NormalizeSessionID(event.SessionID)
		id, err := r.store.CurrentTurn(ctx, session, event.Timestamp)
		if err != nil {
			log.Printf("resolve current turn: %v", err)
			return
		}
		if event.HookEventName != hook.HookSessionEnd.String() {
			r.turns.fill(session, id)
		}
		event.TurnID = id
	}
}

// turnAgent maps a hook agent to the turn/v1 vocabulary; "" for agents
// whose usage is not captured.
func turnAgent(agent string) string {
	switch strings.ToLower(strings.TrimSpace(agent)) {
	case "claude", "claude-code", "claude_code":
		return "claude"
	case "cowork", "claude-cowork", "claude_cowork":
		return "cowork"
	case "codex":
		return "codex"
	default:
		return ""
	}
}

func turnSource(prompt string, isInterrupt *bool) string {
	switch {
	case isInterrupt != nil && *isInterrupt:
		return sqlite.TurnSourceInterrupt
	case strings.HasPrefix(prompt, "/"):
		return sqlite.TurnSourceSlashCommand
	default:
		return sqlite.TurnSourceUserPrompt
	}
}

// turnPrompt decides what a turn says about its prompt. Omitted capture sends
// size only; so does a workspace with the work-type switch off, or without a
// confirmed directive, which clears the switch. Otherwise the excerpt is the
// prompt without harness blocks, redacted with the Merlin review redactor,
// whitespace-collapsed, and bounded to 4,000 bytes under Summaries or 64,000
// under Full payloads. Chars is the original's length in runes; the hash is
// over the trimmed, whitespace-collapsed original, so prompts differing only
// in spacing share a label.
func turnPrompt(prompt string, capture payloadcapture.RuntimeConfiguration) sqlite.TurnPrompt {
	chars := int64(utf8.RuneCountInString(prompt))
	switch {
	case capture.EffectiveMode == payloadcapture.ModeOmitted:
		return sqlite.SizeOnlyTurnPrompt(sqlite.TurnPromptOmitted, chars)
	case !capture.WorkTypeClassification || len(prompt) > maxTurnPromptBytes:
		return sqlite.SizeOnlyTurnPrompt(sqlite.TurnPromptSkipped, chars)
	}
	limit := summaryTurnExcerptBytes
	if capture.EffectiveMode == payloadcapture.ModeFull {
		limit = fullTurnExcerptBytes
	}
	digest := sha256.Sum256([]byte(collapseWhitespace(prompt)))
	// Redact before collapsing whitespace, on text shaped as the rules expect,
	// and before bounding, so a secret across the bound leaves no prefix.
	text := redactMerlinReviewText(modelusage.HarnessBlocks.ReplaceAllString(prompt, " "))
	// Control characters would expand sixfold in the JSON upload.
	text = collapseWhitespace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, text))
	text, truncated := boundedReviewText(text, limit)
	return sqlite.ExcerptTurnPrompt(text, chars, truncated, hex.EncodeToString(digest[:]))
}

func collapseWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
