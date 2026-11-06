package modelusage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/antigravitytools"
)

const antigravitySessionPrefix = "antigravity-"

// NewAntigravityTranscript starts an incremental read of the transcript_full.jsonl
// Antigravity hooks point at. Its format is undocumented: rows carry a step index
// and token counts, but no conversation or model, so the caller says whose it is
// and which model the hooks last reported. A model switch applies to the responses
// read after it; a full reread gives them all the current model.
func NewAntigravityTranscript(session string) *Transcript {
	return &Transcript{kind: "antigravity", state: &antigravityState{session: session, tools: map[string]Tool{}}}
}

// SetModel says which model the transcript's next responses ran on. The rest of
// the formats name theirs and ignore this.
func (t *Transcript) SetModel(model string) {
	if state, ok := t.state.(*antigravityState); ok && model != "" {
		state.model = antigravitytools.BaseModel(model)
	}
}

// antigravityState reads only metadata and reported counts. No prompts,
// arguments, reasoning text or tool output reach its records.
type antigravityState struct {
	line           int
	session, model string
	records        []Record
	// pending are the calls of the last response: the next one consumes their
	// results.
	pending []string
	tools   map[string]Tool
	prompts []Prompt
}

func (s *antigravityState) parseLine(text []byte) error {
	s.line++
	if len(bytes.TrimSpace(text)) == 0 {
		return nil
	}
	var row struct {
		Type       string `json:"type"`
		Source     string `json:"source"`
		StepIndex  *int64 `json:"step_index"`
		CreatedAt  string `json:"created_at"`
		Input      *int64 `json:"input_tokens"`
		Output     *int64 `json:"output_tokens"`
		CacheRead  *int64 `json:"cache_read_tokens"`
		ToolsCalls []struct {
			Name string `json:"name"`
			Args struct {
				ServerName string `json:"ServerName"`
				ToolName   string `json:"ToolName"`
			} `json:"args"`
		} `json:"tool_calls"`
	}
	if err := json.Unmarshal(text, &row); err != nil {
		return fmt.Errorf("antigravity transcript line %d: %w", s.line, err)
	}
	switch row.Type {
	case "USER_INPUT":
		// A system message (a resumed run, a sub-agent's instructions) is no
		// person's prompt.
		if at, err := time.Parse(time.RFC3339Nano, row.CreatedAt); err == nil {
			s.prompts = append(s.prompts, Prompt{SessionID: s.session, Timestamp: at})
		}
	case "PLANNER_RESPONSE":
		if row.StepIndex == nil {
			return fmt.Errorf("antigravity transcript line %d: response without a step", s.line)
		}
		for _, count := range []*int64{row.Input, row.Output, row.CacheRead} {
			if count != nil && (*count < 0 || *count > 1_000_000_000) {
				return fmt.Errorf("antigravity transcript line %d: invalid token count", s.line)
			}
		}
		// The transcript reports no cache writes: Gemini's implicit caching charges
		// none, and the pricer needs the write buckets stated rather than unknown.
		noWrites := int64(0)
		record := Record{
			SessionID:          s.session,
			MessageID:          fmt.Sprintf("step-%d", *row.StepIndex),
			RequestID:          fmt.Sprintf("step-%d", *row.StepIndex),
			Model:              s.model,
			Timestamp:          row.CreatedAt,
			ConsumedToolUseIDs: s.pending,
			Tokens: Tokens{
				InputUncached: row.Input, InputCacheRead: row.CacheRead, Output: row.Output,
				InputCacheWrite: &noWrites, CacheWrite5m: &noWrites, CacheWrite1h: &noWrites,
			},
		}
		// A response's calls run as the steps right after it, in order, and each
		// step number is the call's identity in its hooks.
		conversation := strings.TrimPrefix(s.session, antigravitySessionPrefix)
		s.pending = nil
		for i, call := range row.ToolsCalls {
			id := fmt.Sprintf("agy-%s-%d", conversation, *row.StepIndex+1+int64(i))
			name, ok := antigravitytools.Name(call.Name, call.Args.ServerName, call.Args.ToolName)
			if !ok {
				name = call.Name
			}
			tool := Tool{ID: id, Name: name, Type: "tool_use"}
			if antigravitytools.IsMCP(call.Name) {
				tool.ServerName = call.Args.ServerName
			}
			s.tools[id] = tool
			record.ToolUseIDs = append(record.ToolUseIDs, id)
			s.pending = append(s.pending, id)
		}
		if record.ToolRelated() {
			s.records = append(s.records, record)
		}
	}
	return nil
}

func (s *antigravityState) finish() ([]Record, error) {
	records := make([]Record, 0, len(s.records))
	for _, record := range s.records {
		// A response read before any hook named a model waits for one.
		if record.Model == "" {
			record.Model = s.model
		}
		if record.Model == "" {
			continue
		}
		record.Tools = nil
		for _, id := range append(slices.Clone(record.ToolUseIDs), record.ConsumedToolUseIDs...) {
			if tool, ok := s.tools[id]; ok && !slices.ContainsFunc(record.Tools, func(t Tool) bool { return t.ID == id }) {
				record.Tools = append(record.Tools, tool)
			}
		}
		records = append(records, record)
	}
	return records, nil
}

func (s *antigravityState) promptsSoFar() []Prompt {
	return slices.Clone(s.prompts)
}

func (s *antigravityState) clone() transcriptState {
	c := *s
	c.records, c.pending = slices.Clone(s.records), slices.Clone(s.pending)
	c.prompts = slices.Clone(s.prompts)
	c.tools = maps.Clone(s.tools)
	return &c
}
