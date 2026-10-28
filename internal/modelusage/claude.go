// Package modelusage reads provider-reported usage without estimating token
// counts from tool payloads or treating subscription usage as actual spend.
package modelusage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
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

// Record describes one model message, which may generate several tool calls,
// or a refused attempt billed before it (MessageID "<message>#iteration-N").
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

type cacheCreation struct {
	FiveMinute *int64 `json:"ephemeral_5m_input_tokens"`
	OneHour    *int64 `json:"ephemeral_1h_input_tokens"`
}

type anthropicUsage struct {
	InputTokens              *int64        `json:"input_tokens"`
	CacheReadInputTokens     *int64        `json:"cache_read_input_tokens"`
	CacheCreationInputTokens *int64        `json:"cache_creation_input_tokens"`
	OutputTokens             *int64        `json:"output_tokens"`
	CacheCreation            cacheCreation `json:"cache_creation"`
	OutputTokensDetails      struct {
		Thinking *int64 `json:"thinking_tokens"`
	} `json:"output_tokens_details"`
	// Iterations itemizes a request's attempts, e.g. a refused attempt and
	// the fallback model's. Top-level counts are the attempt that produced
	// the message, the last one.
	Iterations   []anthropicIteration `json:"iterations"`
	ServiceTier  string               `json:"service_tier"`
	InferenceGeo string               `json:"inference_geo"`
	Speed        string               `json:"speed"`
}

type anthropicIteration struct {
	Type                     string        `json:"type"`
	Model                    string        `json:"model"`
	InputTokens              *int64        `json:"input_tokens"`
	CacheReadInputTokens     *int64        `json:"cache_read_input_tokens"`
	CacheCreationInputTokens *int64        `json:"cache_creation_input_tokens"`
	OutputTokens             *int64        `json:"output_tokens"`
	CacheCreation            cacheCreation `json:"cache_creation"`
}

// refusedAttempts returns the iteration indices of the attempts before the one
// that produced the message which are billed on their own, at their own
// model's rates: a model
// that declined after producing output. One that declined before any output
// is billed only for some refusal categories, which the transcript doesn't
// record, so it is left out.
func (u *anthropicUsage) refusedAttempts() []int {
	var attempts []int
	for i, attempt := range u.Iterations[:max(len(u.Iterations)-1, 0)] {
		if attempt.Type == "message" && attempt.Model != "" && attempt.OutputTokens != nil && *attempt.OutputTokens > 0 {
			attempts = append(attempts, i)
		}
	}
	return attempts
}

func (a anthropicIteration) tokens() Tokens {
	t := Tokens{InputUncached: a.InputTokens, InputCacheRead: a.CacheReadInputTokens,
		InputCacheWrite: a.CacheCreationInputTokens, Output: a.OutputTokens}
	if a.CacheCreationInputTokens == nil || a.CacheCreation.within(*a.CacheCreationInputTokens) {
		t.CacheWrite5m, t.CacheWrite1h = a.CacheCreation.FiveMinute, a.CacheCreation.OneHour
	}
	return t
}

// cacheWriteSplit returns the cache write's lifetime split. After a model
// fallback, Claude Code logs the final attempt's write total with the first
// attempt's split, so the iteration whose total matches supplies it. A split
// below the total reports part of the write and is kept as reported; one
// above it contradicts the total and is left out, never a guess.
func (u *anthropicUsage) cacheWriteSplit() (short, long *int64) {
	total, split := u.CacheCreationInputTokens, u.CacheCreation
	if total == nil || (split.FiveMinute == nil && split.OneHour == nil) || split.sums(*total) {
		return split.FiveMinute, split.OneHour
	}
	for _, attempt := range slices.Backward(u.Iterations) {
		if attempt.CacheCreationInputTokens != nil && *attempt.CacheCreationInputTokens == *total && attempt.CacheCreation.sums(*total) {
			return attempt.CacheCreation.FiveMinute, attempt.CacheCreation.OneHour
		}
	}
	if split.within(*total) {
		return split.FiveMinute, split.OneHour
	}
	return nil, nil
}

// maxMessageID is the API's limit on a usage record's message ID.
const maxMessageID = 256

// attemptMessageID names a refused attempt's record. A message ID too long
// to take the suffix within maxMessageID is replaced by its SHA-256.
func attemptMessageID(message string, iteration int) string {
	suffix := fmt.Sprintf("#iteration-%d", iteration)
	if len(message)+len(suffix) > maxMessageID {
		sum := sha256.Sum256([]byte(message))
		message = hex.EncodeToString(sum[:])
	}
	return message + suffix
}

func (c cacheCreation) sum() int64 {
	var sum int64
	for _, count := range []*int64{c.FiveMinute, c.OneHour} {
		if count != nil {
			sum += *count
		}
	}
	return sum
}

func (c cacheCreation) sums(total int64) bool { return c.sum() == total }

// within reports whether the split accounts for no more of the write than
// total. Claude Code sometimes reports a lifetime for only part of a write.
func (c cacheCreation) within(total int64) bool { return c.sum() <= total }

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
		attemptOf:      make(map[int]int),
		pendingResults: make(map[string][]string),
		tools:          make(map[[2]string]Tool),
	}}
}

type claudeState struct {
	line    int
	records []Record
	indices map[[2]string]int
	// attemptOf maps a refused attempt's record to the record of the message
	// its request produced, whose tool links and pricing tier it shares.
	attemptOf map[int]int
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
	short, long := u.cacheWriteSplit()
	tokens := Tokens{
		InputUncached: u.InputTokens, InputCacheRead: u.CacheReadInputTokens,
		InputCacheWrite: u.CacheCreationInputTokens,
		CacheWrite5m:    short, CacheWrite1h: long,
		Output: u.OutputTokens, Thinking: u.OutputTokensDetails.Thinking,
	}
	attempts := u.refusedAttempts()
	checked := []Tokens{tokens}
	for _, i := range attempts {
		checked = append(checked, u.Iterations[i].tokens())
	}
	for _, t := range checked {
		for _, count := range t.fields() {
			if *count != nil && **count < 0 {
				return fmt.Errorf("claude transcript line %d: negative token count", s.line)
			}
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
	// The split is one value: a snapshot that reports either lifetime
	// replaces both. A split kept from an earlier snapshot can exceed this
	// snapshot's total; report it as missing then.
	if short != nil || long != nil {
		record.Tokens.CacheWrite5m, record.Tokens.CacheWrite1h = short, long
	}
	if t := &record.Tokens; t.InputCacheWrite != nil && !(cacheCreation{FiveMinute: t.CacheWrite5m, OneHour: t.CacheWrite1h}).within(*t.InputCacheWrite) {
		t.CacheWrite5m, t.CacheWrite1h = nil, nil
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
	if u.Iterations == nil {
		return nil
	}
	// A snapshot that lists iterations carries each attempt's final usage, so
	// it replaces the attempt's tokens rather than merging into them.
	listed := make(map[string]bool, len(attempts))
	for _, i := range attempts {
		key := [2]string{row.SessionID, attemptMessageID(row.Message.ID, i)}
		listed[key[1]] = true
		attempt, exists := s.indices[key]
		if !exists {
			attempt = len(s.records)
			s.indices[key] = attempt
			s.attemptOf[attempt] = index
			s.records = append(s.records, Record{SessionID: row.SessionID, MessageID: key[1]})
		}
		s.records[attempt].Model, s.records[attempt].Tokens = u.Iterations[i].Model, u.Iterations[i].tokens()
	}
	// An attempt it no longer lists keeps its record with zero usage, so a
	// charge already uploaded is withdrawn by the same upsert.
	for attempt, message := range s.attemptOf {
		if message == index && !listed[s.records[attempt].MessageID] {
			zero := new(int64)
			s.records[attempt].Tokens = Tokens{InputUncached: zero, InputCacheRead: zero, InputCacheWrite: zero,
				CacheWrite5m: zero, CacheWrite1h: zero, Output: zero}
		}
	}
	return nil
}

func (s *claudeState) finish() ([]Record, error) {
	records := slices.Clone(s.records)
	// A refused attempt belongs to the same request as its message: the same
	// tool links, turn and pricing tier. Tool calls are counted by ID, so
	// sharing them doesn't count a call twice.
	for attempt, message := range s.attemptOf {
		r, m := &records[attempt], records[message]
		r.RequestID, r.Timestamp, r.ServiceTier, r.InferenceGeo, r.Speed = m.RequestID, m.Timestamp, m.ServiceTier, m.InferenceGeo, m.Speed
		r.ToolUseIDs, r.ConsumedToolUseIDs = m.ToolUseIDs, slices.Clone(m.ConsumedToolUseIDs)
	}
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
	c := &claudeState{line: s.line, records: slices.Clone(s.records), indices: maps.Clone(s.indices), attemptOf: maps.Clone(s.attemptOf),
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
