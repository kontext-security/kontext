package managedstream

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kontext-security/kontext/internal/guard/store/sqlite"
)

// flushTurns uploads minted turns, each batch with only the sessions its
// turns name. The hosted ledger inserts a turn once and ignores a resent id,
// so a retry after a lost response is harmless. A quarantined turn is
// acknowledged like an accepted one: resending identical bytes would only be
// quarantined again.
func flushTurns(ctx context.Context, opts Options) error {
	store, err := sqlite.OpenStore(opts.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	limit := 50
	for {
		turns, err := store.PendingTurns(ctx, limit)
		if err != nil {
			return err
		}
		if len(turns) == 0 {
			return nil
		}
		var sessionIDs []string
		for _, turn := range turns {
			sessionIDs = append(sessionIDs, turn.SessionID)
		}
		sessions, err := store.AgentSessions(ctx, sessionIDs)
		if err != nil {
			return err
		}
		turns, orphans := withSessionAgents(turns, sessions)
		if len(orphans) > 0 {
			// The hosted ledger refuses a whole batch over a turn without its
			// session. The session row is written before the turn, so one
			// missing now never arrives.
			opts.Diagnostic.Printf("dropping %d turns without an exportable session\n", len(orphans))
			if err := store.AcknowledgeTurns(ctx, orphans); err != nil {
				return err
			}
			continue
		}
		payload := newPayload(opts, sessions, nil, nil, nil, nil, time.Now().UTC())
		payload.Turns = turns
		body, err := encodeTurnsPayload(payload)
		if err != nil {
			return err
		}
		if len(body) > MaxPayloadBytes {
			if limit == 1 {
				return fmt.Errorf("turn record exceeds upload limit")
			}
			limit = (limit + 1) / 2
			continue
		}
		result, err := post(ctx, opts, body)
		if err != nil {
			return err
		}
		if opts.OnFlushSuccess != nil {
			opts.OnFlushSuccess()
		}
		for _, row := range result.Quarantined {
			if row.Kind == "turn" {
				opts.Diagnostic.Printf("hosted ledger quarantined turn %s\n", row.ID)
			}
		}
		ids := make([]string, len(turns))
		for i, turn := range turns {
			ids[i] = turn.ID
		}
		if err := store.AcknowledgeTurns(ctx, ids); err != nil {
			return err
		}
	}
}

// withSessionAgents labels each turn with its session's agent, which the
// hosted ledger requires them to share, and returns the ids of turns whose
// session is missing or not a captured agent.
func withSessionAgents(turns []sqlite.TurnRecord, sessions []sqlite.LedgerRecord) ([]sqlite.TurnRecord, []string) {
	agents := map[string]string{}
	for _, session := range sessions {
		id, _ := session["id"].(string)
		agent, _ := session["agent"].(string)
		switch agent {
		case "claude_code":
			agents[id] = "claude"
		case "claude_cowork":
			agents[id] = "cowork"
		case "codex":
			agents[id] = "codex"
		}
	}
	var orphans []string
	for i, turn := range turns {
		agent, ok := agents[turn.SessionID]
		if !ok {
			orphans = append(orphans, turn.ID)
			continue
		}
		turns[i].Agent = agent
	}
	return turns, orphans
}

// encodeTurnsPayload leaves <, > and & unescaped. Prompt excerpts are prose
// and code, where HTML escaping would make each of those characters six bytes
// and a Full-capture excerpt could outgrow the body limit on its own.
func encodeTurnsPayload(payload Payload) ([]byte, error) {
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(payload); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(body.Bytes(), []byte("\n")), nil
}
