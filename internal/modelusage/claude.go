// Package modelusage reads provider-reported usage without estimating token
// counts from tool payloads or treating subscription usage as actual spend.
package modelusage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"
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
	// TurnID is the daemon-minted turn the message belongs to, set by
	// AssignTurns. Transcript readers never set it.
	TurnID string `json:"turn_id,omitempty"`
}

type Tool struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	ToolsetName string `json:"toolset_name,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
}

// Streamed snapshots can enrich metadata while omitting previously reported
// fields. Retain those fields so later results still link to their tool call.
func mergeToolMetadata(tool, snapshot Tool) Tool {
	for _, field := range []struct {
		dst *string
		src string
	}{
		{&tool.ID, snapshot.ID}, {&tool.Name, snapshot.Name}, {&tool.Type, snapshot.Type},
		{&tool.Namespace, snapshot.Namespace}, {&tool.ToolsetName, snapshot.ToolsetName},
		{&tool.ServerName, snapshot.ServerName},
	} {
		if field.src != "" {
			*field.dst = field.src
		}
	}
	return tool
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
	return NewClaudeTranscript().Read(reader)
}

// NewClaudeTranscript starts an incremental read of a Claude Code transcript.
func NewClaudeTranscript() *Transcript {
	return &Transcript{kind: "claude", state: &claudeState{
		indices:        make(map[[2]string]int),
		pendingResults: make(map[string][]string),
		tools:          make(map[[2]string]Tool),
	}}
}

type claudeState struct {
	line    int
	records []Record
	indices map[[2]string]int
	// Only the next assistant request consumes a tool-result user message.
	// A later ordinary user prompt clears the association.
	pendingResults map[string][]string
	tools          map[[2]string]Tool
	prompts        []Prompt
}

func (s *claudeState) parseLine(text []byte) error {
	s.line++
	if len(bytes.TrimSpace(text)) == 0 {
		return nil
	}
	var envelope struct {
		Type      string          `json:"type"`
		SessionID string          `json:"sessionId"`
		Timestamp string          `json:"timestamp"`
		Message   json.RawMessage `json:"message"`
		// A subagent's transcript is its own file of sidechain rows under the
		// parent's sessionId; its first row reads like a prompt but is the
		// subagent's task. Meta, compact-summary and transcript-only rows are
		// written by Claude Code itself, an auto-compact even mid-turn.
		IsSidechain               bool   `json:"isSidechain"`
		IsMeta                    bool   `json:"isMeta"`
		IsCompactSummary          bool   `json:"isCompactSummary"`
		IsVisibleInTranscriptOnly bool   `json:"isVisibleInTranscriptOnly"`
		Operation                 string `json:"operation"`
		Reason                    string `json:"reason"`
		// A queue operation's prompt text.
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(text, &envelope); err != nil {
		return fmt.Errorf("claude transcript line %d: %w", s.line, err)
	}
	// A prompt submitted while the agent was working is absorbed into the
	// running turn without a user row. Its prompt hook fires at absorption,
	// so it starts a turn as a typed prompt does, unless it is a harness
	// message such as a background task's notification.
	if envelope.Type == "queue-operation" && envelope.Operation == "remove" && envelope.Reason == "absorbed_mid_turn" && !envelope.IsSidechain {
		var prompt string
		if json.Unmarshal(envelope.Content, &prompt) != nil || !IsHarnessEnvelope(prompt) {
			s.addPrompt(envelope.SessionID, envelope.Timestamp)
		}
		return nil
	}
	if envelope.Type == "user" {
		var message struct {
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(envelope.Message, &message); err != nil {
			return fmt.Errorf("claude user message line %d: %w", s.line, err)
		}
		var blocks []struct {
			Type      string `json:"type"`
			ToolUseID string `json:"tool_use_id"`
			Text      string `json:"text"`
		}
		_ = json.Unmarshal(message.Content, &blocks)
		var ids []string
		toolResult := false
		for _, block := range blocks {
			toolResult = toolResult || block.Type == "tool_result"
			if block.Type == "tool_result" && block.ToolUseID != "" {
				ids = append(ids, block.ToolUseID)
			}
		}
		if len(ids) == 0 {
			delete(s.pendingResults, envelope.SessionID)
			// A prompt is a non-empty string or content blocks without a tool
			// result. One whose text is a harness message (a task
			// notification, a session event) starts no turn; image-only
			// content has no text to judge and is a prompt.
			var prompt string
			isPrompt, hasText := false, false
			switch {
			case len(blocks) > 0 && !toolResult:
				isPrompt = true
				var texts []string
				for _, block := range blocks {
					if block.Type == "text" {
						texts, hasText = append(texts, block.Text), true
					}
				}
				prompt = strings.Join(texts, "\n")
			case json.Unmarshal(message.Content, &prompt) == nil && prompt != "":
				isPrompt, hasText = true, true
			}
			if hasText && IsHarnessEnvelope(prompt) {
				isPrompt = false
			}
			if isPrompt && !envelope.IsSidechain && !envelope.IsMeta && !envelope.IsCompactSummary && !envelope.IsVisibleInTranscriptOnly {
				s.addPrompt(envelope.SessionID, envelope.Timestamp)
			}
		} else {
			for _, id := range ids {
				if !slices.Contains(s.pendingResults[envelope.SessionID], id) {
					s.pendingResults[envelope.SessionID] = append(s.pendingResults[envelope.SessionID], id)
				}
			}
		}
		return nil
	}
	if envelope.Type != "assistant" {
		return nil
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
	if err := json.Unmarshal(text, &row); err != nil {
		return fmt.Errorf("claude transcript line %d: %w", s.line, err)
	}
	if row.Message.Usage == nil || row.Message.Model == "<synthetic>" {
		return nil
	}
	if row.SessionID == "" || row.Message.ID == "" || row.Message.Model == "" {
		return fmt.Errorf("claude transcript line %d: usage missing session, message ID, or model", s.line)
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
			return fmt.Errorf("claude transcript line %d: negative token count", s.line)
		}
	}
	key := [2]string{row.SessionID, row.Message.ID}
	index, exists := s.indices[key]
	if !exists {
		index = len(s.records)
		s.indices[key] = index
		s.records = append(s.records, Record{SessionID: row.SessionID, MessageID: row.Message.ID, Model: row.Message.Model})
		s.records[index].ConsumedToolUseIDs = s.pendingResults[row.SessionID]
		delete(s.pendingResults, row.SessionID)
	}
	record := &s.records[index]
	if record.Model != row.Message.Model || (record.RequestID != "" && row.RequestID != "" && record.RequestID != row.RequestID) {
		return fmt.Errorf("claude transcript line %d: conflicting message identity", s.line)
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
			s.tools[key] = mergeToolMetadata(s.tools[key], block)
		}
	}
	return nil
}

func (s *claudeState) finish() ([]Record, error) {
	records := slices.Clone(s.records)
	for i := range records {
		records[i].ToolUseIDs = slices.Clone(records[i].ToolUseIDs)
		seen := make(map[string]bool)
		for _, id := range append(slices.Clone(records[i].ToolUseIDs), records[i].ConsumedToolUseIDs...) {
			if !seen[id] {
				tool := s.tools[[2]string{records[i].SessionID, id}]
				tool.ID = id
				records[i].Tools = append(records[i].Tools, tool)
				seen[id] = true
			}
		}
	}
	return records, nil
}

// addPrompt records a turn boundary. A row without a valid timestamp cannot
// be placed in time and is skipped.
func (s *claudeState) addPrompt(sessionID, timestamp string) {
	at, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil || sessionID == "" {
		return
	}
	s.prompts = append(s.prompts, Prompt{SessionID: sessionID, Timestamp: at})
}

func (s *claudeState) promptsSoFar() []Prompt {
	return slices.Clone(s.prompts)
}

func (s *claudeState) clone() transcriptState {
	c := &claudeState{line: s.line, records: slices.Clone(s.records), indices: maps.Clone(s.indices),
		pendingResults: make(map[string][]string, len(s.pendingResults)), tools: maps.Clone(s.tools), prompts: slices.Clone(s.prompts)}
	for i := range c.records {
		c.records[i].ToolUseIDs = slices.Clone(c.records[i].ToolUseIDs)
	}
	for session, ids := range s.pendingResults {
		c.pendingResults[session] = slices.Clone(ids)
	}
	return c
}

func (t *Tokens) fields() []**int64 {
	return []**int64{&t.InputUncached, &t.InputCacheRead, &t.InputCacheWrite, &t.CacheWrite5m, &t.CacheWrite30m, &t.CacheWrite1h, &t.Output, &t.Thinking}
}
