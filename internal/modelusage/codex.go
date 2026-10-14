package modelusage

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
)

// Codex's current rollout format emits a token_usage_record per OpenAI
// response. Neither turn/thread totals nor event_msg.token_count are charges.
// This adapter intentionally requires that per-response record: older rollout
// formats without it cannot provide the same request identity guarantees.
type codexUsage struct {
	Input     *int64 `json:"input_tokens"`
	Read      *int64 `json:"cached_input_tokens"`
	Write     *int64 `json:"cache_write_input_tokens"`
	Output    *int64 `json:"output_tokens"`
	Reasoning *int64 `json:"reasoning_output_tokens"`
}

func (u codexUsage) tokens() (Tokens, error) {
	t := Tokens{InputCacheRead: u.Read, InputCacheWrite: u.Write, CacheWrite30m: u.Write, Output: u.Output, Thinking: u.Reasoning}
	for _, p := range []*int64{u.Input, u.Read, u.Write, u.Output, u.Reasoning} {
		if p != nil && (*p < 0 || *p > 1_000_000_000) {
			return t, fmt.Errorf("invalid token count")
		}
	}
	if u.Input != nil && u.Read != nil && u.Write != nil {
		n := *u.Input - *u.Read - *u.Write
		if n < 0 {
			return t, fmt.Errorf("cached input exceeds total input")
		}
		t.InputUncached = &n
	}
	if u.Output != nil && u.Reasoning != nil && *u.Reasoning > *u.Output {
		return t, fmt.Errorf("reasoning exceeds output")
	}
	return t, nil
}

// ReadCodexTranscript reads only metadata and reported counts. No prompts,
// arguments, reasoning text, or tool output are included in returned records.
// Tool results become input to the next response, not output of their caller.
func ReadCodexTranscript(reader io.Reader) ([]Record, error) {
	return NewCodexTranscript().Read(reader)
}

// NewCodexTranscript starts an incremental read of a Codex rollout.
func NewCodexTranscript() *Transcript {
	return &Transcript{kind: "codex", state: &codexState{tools: map[string]Tool{}, seen: map[string]bool{}}}
}

// codexState is a rollout's parser state. thread owns the rollout's usage, and
// session is the ID hooks report that thread under: a top-level thread's own
// ID, or for a sub-agent its root thread's.
type codexState struct {
	line                                  int
	records                               []Record
	thread                                string
	session, provider, model, serviceTier string
	current                               *Record
	pending                               []string
	tools                                 map[string]Tool
	seen                                  map[string]bool
	sawLegacy, sawResponse                bool
}

func (s *codexState) parseLine(text []byte) error {
	s.line++
	if len(bytes.TrimSpace(text)) == 0 {
		return nil
	}
	var row struct {
		Timestamp string `json:"timestamp"`
		Type      string `json:"type"`
		Payload   struct {
			Type          string      `json:"type"`
			ID            string      `json:"id"`
			SessionID     string      `json:"session_id"`
			ModelProvider string      `json:"model_provider"`
			Model         string      `json:"model"`
			ServiceTier   string      `json:"service_tier"`
			Role          string      `json:"role"`
			CallID        string      `json:"call_id"`
			Name          string      `json:"name"`
			Namespace     string      `json:"namespace"`
			ToolsetName   string      `json:"toolset_name"`
			ServerName    string      `json:"server_name"`
			ThreadID      string      `json:"thread_id"`
			ResponseID    string      `json:"response_id"`
			Usage         *codexUsage `json:"usage"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(text, &row); err != nil {
		return fmt.Errorf("codex transcript line %d: %w", s.line, err)
	}
	p := row.Payload
	switch row.Type {
	case "session_meta":
		// A sub-agent's rollout starts with its own session_meta and then
		// copies its parent's history, beginning with the parent's
		// session_meta. Only the first names this rollout's thread.
		if s.thread != "" && s.thread != p.ID {
			return nil
		}
		s.thread, s.session, s.provider = p.ID, cmp.Or(p.SessionID, p.ID), p.ModelProvider
	case "turn_context":
		s.model, s.serviceTier = p.Model, p.ServiceTier
		if p.ModelProvider != "" {
			s.provider = p.ModelProvider
		}
	case "compacted":
		s.current, s.pending = nil, nil
	case "event_msg":
		switch p.Type {
		case "token_count":
			s.sawLegacy = true
		case "task_started", "task_complete", "turn_aborted":
			s.current, s.pending = nil, nil
		}
	case "response_item":
		switch p.Type {
		case "function_call_output", "custom_tool_call_output":
			if p.CallID != "" && s.tools[p.CallID].Name != "" && !slices.Contains(s.pending, p.CallID) {
				s.pending = append(s.pending, p.CallID)
			}
		case "message":
			if p.Role == "user" {
				s.pending = nil
			}
			if p.Role != "assistant" {
				return nil
			}
			fallthrough
		case "reasoning", "function_call", "custom_tool_call":
			if s.current == nil {
				s.current = &Record{Model: s.model, ServiceTier: s.serviceTier, Timestamp: row.Timestamp, ConsumedToolUseIDs: s.pending}
				s.pending = nil
			}
			if (p.Type == "function_call" || p.Type == "custom_tool_call") && p.CallID != "" {
				if !slices.Contains(s.current.ToolUseIDs, p.CallID) {
					s.current.ToolUseIDs = append(s.current.ToolUseIDs, p.CallID)
				}
				s.tools[p.CallID] = mergeToolMetadata(s.tools[p.CallID], Tool{ID: p.CallID, Name: p.Name, Type: p.Type,
					Namespace: p.Namespace, ToolsetName: p.ToolsetName, ServerName: p.ServerName})
			}
		}
	case "token_usage_record":
		s.sawResponse = true
		// Forks and sub-agents can contain copied parent history. The recorded
		// owning thread, rather than a filename or current hook, determines
		// which usage belongs here.
		if s.provider != "openai" || s.thread == "" || p.ThreadID != s.thread {
			s.current, s.pending = nil, nil
			return nil
		}
		if p.ResponseID == "" || p.Usage == nil {
			return fmt.Errorf("codex usage missing response identity or counters")
		}
		if s.seen[p.ResponseID] {
			return nil
		}
		s.seen[p.ResponseID] = true
		if s.current == nil {
			return nil
		} // No observable tool/model output association.
		s.current.SessionID = "codex-" + strings.TrimPrefix(s.session, "codex-")
		s.current.MessageID, s.current.RequestID = p.ResponseID, p.ResponseID
		s.current.Timestamp = row.Timestamp
		if s.current.Model == "" {
			return fmt.Errorf("codex usage missing model")
		}
		tokens, err := p.Usage.tokens()
		if err != nil {
			return fmt.Errorf("codex transcript line %d: %w", s.line, err)
		}
		s.current.Tokens = tokens
		if s.current.ToolRelated() {
			s.records = append(s.records, *s.current)
		}
		s.current = nil
	}
	return nil
}

func (s *codexState) finish() ([]Record, error) {
	if s.provider == "openai" && s.sawLegacy && !s.sawResponse {
		return nil, fmt.Errorf("unsupported Codex transcript: per-response token_usage_record required")
	}
	// Finished records never change, so only their tool lists are rebuilt.
	records := slices.Clone(s.records)
	for i := range records {
		for _, id := range append(slices.Clone(records[i].ToolUseIDs), records[i].ConsumedToolUseIDs...) {
			if !slices.ContainsFunc(records[i].Tools, func(t Tool) bool { return t.ID == id }) {
				records[i].Tools = append(records[i].Tools, s.tools[id])
			}
		}
	}
	return records, nil
}

func (s *codexState) clone() transcriptState {
	c := *s
	c.records, c.pending = slices.Clone(s.records), slices.Clone(s.pending)
	c.tools, c.seen = maps.Clone(s.tools), maps.Clone(s.seen)
	if s.current != nil {
		current := *s.current
		current.ToolUseIDs = slices.Clone(current.ToolUseIDs)
		c.current = &current
	}
	return &c
}
