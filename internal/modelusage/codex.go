package modelusage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	scanner.Split(completeLines)
	var records []Record
	var session, provider, model, serviceTier string
	var current *Record
	var pending []string
	tools := map[string]Tool{}
	seen := map[string]bool{}
	sawLegacy, sawResponse := false, false
	line := 0
	for scanner.Scan() {
		line++
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var row struct {
			Timestamp string `json:"timestamp"`
			Type      string `json:"type"`
			Payload   struct {
				Type          string      `json:"type"`
				ID            string      `json:"id"`
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
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, fmt.Errorf("codex transcript line %d: %w", line, err)
		}
		p := row.Payload
		switch row.Type {
		case "session_meta":
			if session != "" && session != p.ID {
				return nil, fmt.Errorf("codex transcript has conflicting session IDs")
			}
			session, provider = p.ID, p.ModelProvider
		case "turn_context":
			model, serviceTier = p.Model, p.ServiceTier
			if p.ModelProvider != "" {
				provider = p.ModelProvider
			}
		case "compacted":
			current, pending = nil, nil
		case "event_msg":
			switch p.Type {
			case "token_count":
				sawLegacy = true
			case "task_started", "task_complete", "turn_aborted":
				current, pending = nil, nil
			}
		case "response_item":
			switch p.Type {
			case "function_call_output", "custom_tool_call_output":
				if p.CallID != "" && tools[p.CallID].Name != "" && !slices.Contains(pending, p.CallID) {
					pending = append(pending, p.CallID)
				}
			case "message":
				if p.Role == "user" {
					pending = nil
				}
				if p.Role != "assistant" {
					continue
				}
				fallthrough
			case "reasoning", "function_call", "custom_tool_call":
				if current == nil {
					current = &Record{Model: model, ServiceTier: serviceTier, Timestamp: row.Timestamp, ConsumedToolUseIDs: pending}
					pending = nil
				}
				if (p.Type == "function_call" || p.Type == "custom_tool_call") && p.CallID != "" {
					if !slices.Contains(current.ToolUseIDs, p.CallID) {
						current.ToolUseIDs = append(current.ToolUseIDs, p.CallID)
					}
					tools[p.CallID] = Tool{ID: p.CallID, Name: p.Name, Type: p.Type,
						Namespace: p.Namespace, ToolsetName: p.ToolsetName, ServerName: p.ServerName}
				}
			}
		case "token_usage_record":
			sawResponse = true
			// Forks can contain copied parent history. The recorded owning thread,
			// rather than a filename or current hook, determines which usage belongs here.
			if provider != "openai" || session == "" || p.ThreadID != session {
				current, pending = nil, nil
				continue
			}
			if p.ResponseID == "" || p.Usage == nil {
				return nil, fmt.Errorf("codex usage missing response identity or counters")
			}
			if seen[p.ResponseID] {
				continue
			}
			seen[p.ResponseID] = true
			if current == nil {
				continue
			} // No observable tool/model output association.
			current.SessionID = "codex-" + strings.TrimPrefix(session, "codex-")
			current.MessageID, current.RequestID = p.ResponseID, p.ResponseID
			current.Timestamp = row.Timestamp
			if current.Model == "" {
				return nil, fmt.Errorf("codex usage missing model")
			}
			tokens, err := p.Usage.tokens()
			if err != nil {
				return nil, fmt.Errorf("codex transcript line %d: %w", line, err)
			}
			current.Tokens = tokens
			if current.ToolRelated() {
				records = append(records, *current)
			}
			current = nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read codex transcript: %w", err)
	}
	if provider == "openai" && sawLegacy && !sawResponse {
		return nil, fmt.Errorf("unsupported Codex transcript: per-response token_usage_record required")
	}
	for i := range records {
		for _, id := range append(slices.Clone(records[i].ToolUseIDs), records[i].ConsumedToolUseIDs...) {
			if !slices.ContainsFunc(records[i].Tools, func(t Tool) bool { return t.ID == id }) {
				records[i].Tools = append(records[i].Tools, tools[id])
			}
		}
	}
	return records, nil
}
