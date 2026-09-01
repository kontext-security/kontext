package stepsafety

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
)

const (
	maxContextSessions  = 256
	maxHistoryEntries   = 24
	maxHistoryBytes     = maxPretokenizedFieldBytes
	maxUserRequestBytes = maxPretokenizedFieldBytes
)

type HistoryEntry struct {
	ToolName      string
	ToolArguments map[string]any
	ToolResponse  map[string]any
	Error         string
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
		encoded, err := serializeHistory(ctx.history)
		if err == nil && len(encoded) <= maxHistoryBytes {
			break
		}
		ctx.history = append([]HistoryEntry(nil), ctx.history[1:]...)
	}
	if encoded, err := serializeHistory(ctx.history); err != nil || len(encoded) > maxHistoryBytes {
		ctx.history = []HistoryEntry{{
			ToolName: entry.ToolName,
			Error:    "oversized structured observation omitted",
		}}
	}
}

func (s *ContextStore) Snapshot(sessionID string) (userRequest, interactionHistory string) {
	if s == nil || sessionID == "" {
		return "", "[]"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx := s.sessions[sessionID]
	if ctx == nil {
		return "", "[]"
	}
	s.serial++
	ctx.serial = s.serial
	encoded, err := serializeHistory(ctx.history)
	if err != nil {
		return ctx.request, "[]"
	}
	return ctx.request, encoded
}

// serializeHistory implements the exact structured-history representation used
// to train the v2 encoder: a compact, key-sorted JSON array with tool,
// arguments, and string observation fields. Empty history is always [].
// Tool results remain inert text so their contents can never become a trusted
// instruction channel through a richer runtime type.
func serializeHistory(entries []HistoryEntry) (string, error) {
	events := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.ToolName) == "" {
			continue
		}
		event := map[string]any{"tool": entry.ToolName}
		if entry.ToolArguments != nil {
			event["arguments"] = entry.ToolArguments
		}
		if observation, ok, err := observationText(entry.ToolResponse, entry.Error); err != nil {
			return "", err
		} else if ok {
			event["observation"] = observation
		}
		events = append(events, event)
	}
	return compactSortedJSON(events)
}

func observationText(response map[string]any, errorText string) (string, bool, error) {
	if response == nil {
		if errorText == "" {
			return "", false, nil
		}
		return errorText, true, nil
	}
	if errorText == "" {
		encoded, err := compactSortedJSON(response)
		return encoded, true, err
	}
	encoded, err := compactSortedJSON(map[string]any{
		"error":    errorText,
		"response": response,
	})
	return encoded, true, err
}

// compactSortedJSON matches Python json.dumps(..., ensure_ascii=False,
// sort_keys=True, separators=(",", ":")) for the JSON values admitted by the
// hook adapters. encoding/json sorts object keys; disabling HTML escaping keeps
// ordinary Unicode and symbols byte-compatible with the training proxy.
func compactSortedJSON(value any) (string, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return "", err
	}
	return unescapeJSONLineSeparators(strings.TrimSuffix(output.String(), "\n")), nil
}

// encoding/json always escapes U+2028 and U+2029 for legacy JSONP safety,
// while Python ensure_ascii=False keeps them as UTF-8. Only decode genuine JSON
// escapes here; an input string containing the literal text `\u2028` must keep
// its leading backslash.
func unescapeJSONLineSeparators(value string) string {
	if !strings.Contains(value, `\u2028`) && !strings.Contains(value, `\u2029`) {
		return value
	}
	var output strings.Builder
	output.Grow(len(value))
	for index := 0; index < len(value); {
		if index+6 <= len(value) && (value[index:index+6] == `\u2028` || value[index:index+6] == `\u2029`) {
			precedingSlashes := 0
			for prior := index - 1; prior >= 0 && value[prior] == '\\'; prior-- {
				precedingSlashes++
			}
			if precedingSlashes%2 == 0 {
				if value[index+5] == '8' {
					output.WriteRune('\u2028')
				} else {
					output.WriteRune('\u2029')
				}
				index += 6
				continue
			}
		}
		output.WriteByte(value[index])
		index++
	}
	return output.String()
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
