package stepsafety

import (
	"encoding/json"
	"sync"
)

const (
	maxContextSessions  = 256
	maxHistoryEntries   = 24
	maxHistoryBytes     = maxPretokenizedFieldBytes
	maxUserRequestBytes = maxPretokenizedFieldBytes
)

type HistoryEntry struct {
	ToolName      string         `json:"tool_name"`
	ToolArguments map[string]any `json:"tool_arguments,omitempty"`
	ToolResponse  map[string]any `json:"tool_response,omitempty"`
	Error         string         `json:"error,omitempty"`
}

type sessionContext struct {
	request string
	history []HistoryEntry
	serial  uint64
}

// ContextStore keeps only production-visible, structured hook data. It never
// reads transcripts or assistant messages, so agent Thought/reasoning cannot
// enter the model through this history path. The store is memory-only and
// bounded; raw context is never part of telemetry.
type ContextStore struct {
	mu       sync.Mutex
	sessions map[string]*sessionContext
	serial   uint64
}

func NewContextStore() *ContextStore {
	return &ContextStore{sessions: make(map[string]*sessionContext)}
}

func (s *ContextStore) RecordUserRequest(sessionID, request string) {
	if s == nil || sessionID == "" || request == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := s.session(sessionID)
	ctx.request = truncateUTF8Head(request, maxUserRequestBytes)
}

func truncateUTF8Head(value string, max int) string {
	if len(value) <= max {
		return value
	}
	cut := max
	for cut > 0 && value[cut]&0xC0 == 0x80 {
		cut--
	}
	return value[:cut]
}

func (s *ContextStore) RecordInteraction(sessionID string, entry HistoryEntry) {
	if s == nil || sessionID == "" || entry.ToolName == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := s.session(sessionID)
	ctx.history = append(ctx.history, entry)
	if len(ctx.history) > maxHistoryEntries {
		ctx.history = append([]HistoryEntry(nil), ctx.history[len(ctx.history)-maxHistoryEntries:]...)
	}
	for len(ctx.history) > 1 {
		encoded, err := json.Marshal(ctx.history)
		if err == nil && len(encoded) <= maxHistoryBytes {
			break
		}
		ctx.history = append([]HistoryEntry(nil), ctx.history[1:]...)
	}
	if encoded, err := json.Marshal(ctx.history); err != nil || len(encoded) > maxHistoryBytes {
		ctx.history = []HistoryEntry{{
			ToolName: entry.ToolName,
			Error:    "oversized structured interaction omitted",
		}}
	}
}

func (s *ContextStore) Snapshot(sessionID string) (userRequest, interactionHistory string) {
	if s == nil || sessionID == "" {
		return "", ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := s.sessions[sessionID]
	if ctx == nil {
		return "", ""
	}
	s.serial++
	ctx.serial = s.serial
	encoded, err := json.Marshal(ctx.history)
	if err != nil || len(ctx.history) == 0 {
		return ctx.request, ""
	}
	return ctx.request, string(encoded)
}

func (s *ContextStore) CloseSession(sessionID string) {
	if s == nil || sessionID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

func (s *ContextStore) session(sessionID string) *sessionContext {
	if existing := s.sessions[sessionID]; existing != nil {
		s.serial++
		existing.serial = s.serial
		return existing
	}
	if len(s.sessions) >= maxContextSessions {
		var oldestID string
		var oldest uint64
		for id, candidate := range s.sessions {
			if oldestID == "" || candidate.serial < oldest {
				oldestID, oldest = id, candidate.serial
			}
		}
		delete(s.sessions, oldestID)
	}
	s.serial++
	created := &sessionContext{serial: s.serial}
	s.sessions[sessionID] = created
	return created
}
