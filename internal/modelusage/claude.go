// Package modelusage reads provider-reported usage without estimating token
// counts from tool payloads or treating subscription usage as actual spend.
package modelusage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

// Tokens contains disjoint input buckets and total model output. Missing values
// remain nil. Cache write durations and thinking are subsets, not extra tokens.
type Tokens struct {
	InputUncached   *int64 `json:"input_uncached"`
	InputCacheRead  *int64 `json:"input_cache_read"`
	InputCacheWrite *int64 `json:"input_cache_write"`
	CacheWrite5m    *int64 `json:"cache_write_5m"`
	CacheWrite30m   *int64 `json:"cache_write_30m,omitempty"`
	CacheWrite1h    *int64 `json:"cache_write_1h"`
	Output          *int64 `json:"output"`
	Thinking        *int64 `json:"thinking"`
}

// Record describes one model message, which may generate several tool calls.
// ToolUseIDs correlate tools with a message; they do not allocate its cost.
// Consumers must upsert by (SessionID, MessageID) across transcript reads.
type Record struct {
	SessionID          string   `json:"session_id"`
	MessageID          string   `json:"message_id"`
	RequestID          string   `json:"request_id,omitempty"`
	Model              string   `json:"model"`
	Timestamp          string   `json:"timestamp"`
	ToolUseIDs         []string `json:"tool_use_ids,omitempty"`
	ConsumedToolUseIDs []string `json:"consumed_tool_use_ids,omitempty"`
	Tools              []Tool   `json:"tools,omitempty"`
	Tokens             Tokens   `json:"tokens"`
	ServiceTier        string   `json:"service_tier,omitempty"`
	InferenceGeo       string   `json:"inference_geo,omitempty"`
	Speed              string   `json:"speed,omitempty"`
}

type Tool struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	ToolsetName string `json:"toolset_name,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
}

func (r Record) ToolRelated() bool {
	return len(r.ToolUseIDs) > 0 || len(r.ConsumedToolUseIDs) > 0
}

type anthropicUsage struct {
	InputTokens              *int64 `json:"input_tokens"`
	CacheReadInputTokens     *int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens *int64 `json:"cache_creation_input_tokens"`
	OutputTokens             *int64 `json:"output_tokens"`
	CacheCreation            struct {
		FiveMinute *int64 `json:"ephemeral_5m_input_tokens"`
		OneHour    *int64 `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`
	OutputTokensDetails struct {
		Thinking *int64 `json:"thinking_tokens"`
	} `json:"output_tokens_details"`
	ServiceTier  string `json:"service_tier"`
	InferenceGeo string `json:"inference_geo"`
	Speed        string `json:"speed"`
}

// ReadClaudeTranscript reads complete JSONL records from a Claude Code
// transcript. The unfinished trailing line is left for the next read. Repeated
// content blocks sharing a message ID update the same usage snapshot instead
// of adding its counters again. This function does not watch files, persist
// records, or infer Cowork transcript locations.
func ReadClaudeTranscript(reader io.Reader) ([]Record, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	scanner.Split(completeLines)
	var records []Record
	indices := make(map[[2]string]int)
	// Only the next assistant request consumes a tool-result user message.
	// A later ordinary user prompt clears the association.
	pendingResults := make(map[string][]string)
	tools := make(map[[2]string]Tool)
	line := 0
	for scanner.Scan() {
		line++
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var envelope struct {
			Type      string          `json:"type"`
			SessionID string          `json:"sessionId"`
			Message   json.RawMessage `json:"message"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &envelope); err != nil {
			return nil, fmt.Errorf("claude transcript line %d: %w", line, err)
		}
		if envelope.Type == "user" {
			var message struct {
				Content json.RawMessage `json:"content"`
			}
			if err := json.Unmarshal(envelope.Message, &message); err != nil {
				return nil, fmt.Errorf("claude user message line %d: %w", line, err)
			}
			var blocks []struct {
				Type      string `json:"type"`
				ToolUseID string `json:"tool_use_id"`
			}
			_ = json.Unmarshal(message.Content, &blocks)
			var ids []string
			for _, block := range blocks {
				if block.Type == "tool_result" && block.ToolUseID != "" {
					ids = append(ids, block.ToolUseID)
				}
			}
			if len(ids) == 0 {
				delete(pendingResults, envelope.SessionID)
			} else {
				for _, id := range ids {
					if !slices.Contains(pendingResults[envelope.SessionID], id) {
						pendingResults[envelope.SessionID] = append(pendingResults[envelope.SessionID], id)
					}
				}
			}
			continue
		}
		if envelope.Type != "assistant" {
			continue
		}
		var row struct {
			SessionID string `json:"sessionId"`
			RequestID string `json:"requestId"`
			Timestamp string `json:"timestamp"`
			Message   struct {
				ID      string          `json:"id"`
				Model   string          `json:"model"`
				Usage   *anthropicUsage `json:"usage"`
				Content []Tool          `json:"content"`
			} `json:"message"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, fmt.Errorf("claude transcript line %d: %w", line, err)
		}
		if row.Message.Usage == nil || row.Message.Model == "<synthetic>" {
			continue
		}
		if row.SessionID == "" || row.Message.ID == "" || row.Message.Model == "" {
			return nil, fmt.Errorf("claude transcript line %d: usage missing session, message ID, or model", line)
		}
		u := row.Message.Usage
		tokens := Tokens{
			InputUncached: u.InputTokens, InputCacheRead: u.CacheReadInputTokens,
			InputCacheWrite: u.CacheCreationInputTokens,
			CacheWrite5m:    u.CacheCreation.FiveMinute, CacheWrite1h: u.CacheCreation.OneHour,
			Output: u.OutputTokens, Thinking: u.OutputTokensDetails.Thinking,
		}
		for _, count := range tokens.fields() {
			if *count != nil && **count < 0 {
				return nil, fmt.Errorf("claude transcript line %d: negative token count", line)
			}
		}
		key := [2]string{row.SessionID, row.Message.ID}
		index, exists := indices[key]
		if !exists {
			index = len(records)
			indices[key] = index
			records = append(records, Record{SessionID: row.SessionID, MessageID: row.Message.ID, Model: row.Message.Model})
			records[index].ConsumedToolUseIDs = pendingResults[row.SessionID]
			delete(pendingResults, row.SessionID)
		}
		record := &records[index]
		if record.Model != row.Message.Model || (record.RequestID != "" && row.RequestID != "" && record.RequestID != row.RequestID) {
			return nil, fmt.Errorf("claude transcript line %d: conflicting message identity", line)
		}
		if row.RequestID != "" {
			record.RequestID = row.RequestID
		}
		if row.Timestamp != "" {
			record.Timestamp = row.Timestamp
		}
		// Later snapshots can add fields or revise cumulative output counts.
		previous := record.Tokens.fields()
		for i, count := range tokens.fields() {
			if *count != nil {
				*previous[i] = *count
			}
		}
		for _, field := range []struct {
			dst *string
			src string
		}{
			{&record.ServiceTier, u.ServiceTier}, {&record.InferenceGeo, u.InferenceGeo}, {&record.Speed, u.Speed},
		} {
			if field.src != "" {
				*field.dst = field.src
			}
		}
		for _, block := range row.Message.Content {
			if block.Type == "tool_use" && block.ID != "" {
				if !slices.Contains(record.ToolUseIDs, block.ID) {
					record.ToolUseIDs = append(record.ToolUseIDs, block.ID)
				}
				key := [2]string{row.SessionID, block.ID}
				// Streamed snapshots can add metadata; missing later fields must
				// not erase an earlier name or toolset identity.
				tool := tools[key]
				tool.ID = block.ID
				for _, field := range []struct {
					dst *string
					src string
				}{
					{&tool.Name, block.Name}, {&tool.Type, block.Type},
					{&tool.Namespace, block.Namespace}, {&tool.ToolsetName, block.ToolsetName},
					{&tool.ServerName, block.ServerName},
				} {
					if field.src != "" {
						*field.dst = field.src
					}
				}
				tools[key] = tool
			}
		}
	}
	for i := range records {
		seen := make(map[string]bool)
		for _, id := range append(slices.Clone(records[i].ToolUseIDs), records[i].ConsumedToolUseIDs...) {
			if !seen[id] {
				tool := tools[[2]string{records[i].SessionID, id}]
				tool.ID = id
				records[i].Tools = append(records[i].Tools, tool)
				seen[id] = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read claude transcript: %w", err)
	}
	return records, nil
}

func (t *Tokens) fields() []**int64 {
	return []**int64{&t.InputUncached, &t.InputCacheRead, &t.InputCacheWrite, &t.CacheWrite5m, &t.CacheWrite30m, &t.CacheWrite1h, &t.Output, &t.Thinking}
}

func completeLines(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && json.Valid(data) {
		return len(data), data, nil
	}
	if atEOF {
		return len(data), nil, nil
	}
	return 0, nil, nil
}
