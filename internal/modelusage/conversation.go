package modelusage

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
)

// Message is one entry of a transcript the model saw: text a person or the
// assistant wrote, an assistant tool call, or a tool result.
type Message struct {
	// Role is "user", "assistant" or "tool".
	Role string
	Text string
	// ToolCall is set on an assistant tool call.
	ToolCall *ToolCall
	// ToolUseID names the call a tool result answers.
	ToolUseID string
	// Response groups the entries of one model response: Claude's message
	// ID, or a counter for Codex, whose rollouts carry none.
	Response string
	// Prompt marks a person's prompt, which starts a turn.
	Prompt bool
}

type ToolCall struct {
	ID    string
	Name  string
	Input json.RawMessage
}

// Conversation is what the model saw of a transcript, in file order, and the
// model that wrote its latest assistant message.
type Conversation struct {
	Messages []Message
	Model    string
	// Compacted is set when the read met a compaction: Messages then start
	// after it, which is where the model's view of the conversation starts.
	Compacted bool
}

// ReadClaudeConversation reads the model-visible messages of a Claude Code
// transcript. Lines that do not parse are skipped, so a read that starts
// mid-file loses only its first, partial line. Thinking, system reminders and
// rows Claude Code writes for itself are left out, and a compaction drops what
// came before it. Sidechain rows are a subagent's: they are read only from a
// subagent's own transcript, and left out of a parent's that carries them.
func ReadClaudeConversation(reader io.Reader, subagent bool) Conversation {
	var conversation Conversation
	scanLines(reader, func(line []byte) {
		var row struct {
			Type                      string `json:"type"`
			Subtype                   string `json:"subtype"`
			IsSidechain               bool   `json:"isSidechain"`
			IsMeta                    bool   `json:"isMeta"`
			IsCompactSummary          bool   `json:"isCompactSummary"`
			IsVisibleInTranscriptOnly bool   `json:"isVisibleInTranscriptOnly"`
			Message                   struct {
				ID      string          `json:"id"`
				Model   string          `json:"model"`
				Content json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(line, &row) != nil || row.IsSidechain && !subagent {
			return
		}
		if row.Type == "system" && row.Subtype == "compact_boundary" {
			conversation.Messages, conversation.Compacted = nil, true
			return
		}
		if row.Type != "user" && row.Type != "assistant" || row.IsMeta || row.IsCompactSummary || row.IsVisibleInTranscriptOnly {
			return
		}
		var text string
		if json.Unmarshal(row.Message.Content, &text) == nil {
			if row.Type == "user" {
				conversation.addUserText(text)
			} else if text != "" {
				conversation.Messages = append(conversation.Messages, Message{Role: "assistant", Text: text, Response: row.Message.ID})
			}
			return
		}
		var blocks []struct {
			Type      string          `json:"type"`
			Text      string          `json:"text"`
			ID        string          `json:"id"`
			Name      string          `json:"name"`
			Input     json.RawMessage `json:"input"`
			ToolUseID string          `json:"tool_use_id"`
			Content   json.RawMessage `json:"content"`
		}
		if json.Unmarshal(row.Message.Content, &blocks) != nil {
			return
		}
		if row.Type == "assistant" && row.Message.Model != "" && row.Message.Model != "<synthetic>" {
			conversation.Model = row.Message.Model
		}
		for _, block := range blocks {
			switch {
			case row.Type == "user" && block.Type == "text":
				conversation.addUserText(block.Text)
			case row.Type == "user" && block.Type == "tool_result":
				conversation.Messages = append(conversation.Messages, Message{Role: "tool", Text: claudeResultText(block.Content), ToolUseID: block.ToolUseID})
			case row.Type == "assistant" && block.Type == "text" && block.Text != "":
				conversation.Messages = append(conversation.Messages, Message{Role: "assistant", Text: block.Text, Response: row.Message.ID})
			case row.Type == "assistant" && block.Type == "tool_use":
				conversation.Messages = append(conversation.Messages, Message{Role: "assistant", Response: row.Message.ID,
					ToolCall: &ToolCall{ID: block.ID, Name: block.Name, Input: block.Input}})
			}
		}
	})
	return conversation
}

// addUserText adds a person's text without the reminders the harness wraps
// around it. A harness message, such as a background task's notification,
// was still shown to the model, but starts no turn.
func (c *Conversation) addUserText(text string) {
	visible := WithoutSystemReminders(text)
	if visible == "" {
		return
	}
	c.Messages = append(c.Messages, Message{Role: "user", Text: visible, Prompt: !IsHarnessEnvelope(text)})
}

// WithoutSystemReminders is text without the system reminders an agent
// harness adds to it.
func WithoutSystemReminders(text string) string {
	return strings.TrimSpace(systemReminderBlocks.ReplaceAllString(text, ""))
}

// claudeResultText is a tool result's text: a string, or its text blocks.
func claudeResultText(content json.RawMessage) string {
	var text string
	if json.Unmarshal(content, &text) == nil {
		return text
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) != nil {
		return ""
	}
	var texts []string
	for _, block := range blocks {
		switch block.Type {
		case "text":
			texts = append(texts, block.Text)
		case "image":
			texts = append(texts, "[image]")
		}
	}
	return strings.Join(texts, "\n")
}

// ReadCodexConversation reads the model-visible messages of a Codex rollout:
// user and assistant messages, tool calls and their outputs. Injected context
// (environment, app integrations) and reasoning are left out. A compaction
// replaces what came before it with the history it carries, which is what the
// model sees from then on. Lines that do not parse are skipped.
func ReadCodexConversation(reader io.Reader) Conversation {
	var conversation Conversation
	responses, inResponse := 0, false
	// Consecutive assistant items are one response.
	response := func() string {
		if !inResponse {
			responses, inResponse = responses+1, true
		}
		return strconv.Itoa(responses)
	}
	addItem := func(raw json.RawMessage) {
		var item struct {
			Type      string          `json:"type"`
			Role      string          `json:"role"`
			Content   json.RawMessage `json:"content"`
			Name      string          `json:"name"`
			Arguments string          `json:"arguments"`
			Input     string          `json:"input"`
			CallID    string          `json:"call_id"`
			Output    json.RawMessage `json:"output"`
		}
		if json.Unmarshal(raw, &item) != nil {
			return
		}
		switch item.Type {
		case "message":
			text := codexMessageText(item.Content)
			switch item.Role {
			case "user":
				inResponse = false
				if text != "" && !codexHarnessMessage(item.Content) {
					conversation.addUserText(text)
				}
			case "assistant":
				if text != "" {
					conversation.Messages = append(conversation.Messages, Message{Role: "assistant", Text: text, Response: response()})
				}
			}
		case "function_call", "custom_tool_call":
			// A function call's arguments are JSON text; a custom tool's input
			// is free text.
			input := json.RawMessage(item.Arguments)
			if item.Type == "custom_tool_call" {
				input, _ = json.Marshal(item.Input)
			} else if !json.Valid(input) {
				input, _ = json.Marshal(item.Arguments)
			}
			conversation.Messages = append(conversation.Messages, Message{Role: "assistant", Response: response(),
				ToolCall: &ToolCall{ID: item.CallID, Name: item.Name, Input: input}})
		case "function_call_output", "custom_tool_call_output":
			inResponse = false
			conversation.Messages = append(conversation.Messages, Message{Role: "tool", Text: codexOutputText(item.Output), ToolUseID: item.CallID})
		}
	}
	scanLines(reader, func(line []byte) {
		var row struct {
			Type    string          `json:"type"`
			Payload json.RawMessage `json:"payload"`
		}
		if json.Unmarshal(line, &row) != nil {
			return
		}
		switch row.Type {
		case "turn_context":
			var context struct {
				Model string `json:"model"`
			}
			if json.Unmarshal(row.Payload, &context) == nil && context.Model != "" {
				conversation.Model = context.Model
			}
		case "compacted":
			var compacted struct {
				ReplacementHistory []json.RawMessage `json:"replacement_history"`
			}
			_ = json.Unmarshal(row.Payload, &compacted)
			conversation.Messages, conversation.Compacted, inResponse = nil, true, false
			for _, item := range compacted.ReplacementHistory {
				addItem(item)
			}
		case "response_item":
			addItem(row.Payload)
		}
	})
	return conversation
}

// CodexCommandExit reads a Codex rollout for how the command of an
// exec_command call ended: its exit code, once the command finished and
// before any of the call's output went to the model. Codex writes the
// finished command before it runs PostToolUse hooks, and the output after.
// A call from code mode or write_stdin, and one whose command was still
// running when exec_command returned, reports false.
func CodexCommandExit(reader io.Reader, callID string) (int, bool) {
	var called, answered bool
	var exitCode *int
	scanLines(reader, func(line []byte) {
		if callID == "" || !bytes.Contains(line, []byte(callID)) {
			return
		}
		var row struct {
			Type    string `json:"type"`
			Payload struct {
				Type   string `json:"type"`
				Name   string `json:"name"`
				CallID string `json:"call_id"`
				Item   struct {
					Type     string `json:"type"`
					ID       string `json:"id"`
					ExitCode *int   `json:"exit_code"`
				} `json:"item"`
			} `json:"payload"`
		}
		if json.Unmarshal(line, &row) != nil {
			return
		}
		payload := row.Payload
		switch {
		case row.Type == "response_item" && payload.Type == "function_call" && payload.CallID == callID:
			called = payload.Name == "exec_command"
		case row.Type == "response_item" && payload.Type == "function_call_output" && payload.CallID == callID:
			answered = true
		case row.Type == "event_msg" && payload.Type == "item_completed" && payload.Item.Type == "CommandExecution" && payload.Item.ID == callID:
			exitCode = payload.Item.ExitCode
		}
	})
	if !called || answered || exitCode == nil {
		return 0, false
	}
	return *exitCode, true
}

func codexMessageText(content json.RawMessage) string {
	var parts []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &parts) != nil {
		return ""
	}
	var texts []string
	for _, part := range parts {
		if part.Text != "" {
			texts = append(texts, part.Text)
		}
	}
	return strings.Join(texts, "\n")
}

// codexOutputText is a tool output's text: a string, its text items, or the
// content of an object that carries one.
func codexOutputText(output json.RawMessage) string {
	var text string
	if json.Unmarshal(output, &text) == nil {
		return text
	}
	if text := codexMessageText(output); text != "" {
		return text
	}
	var object struct {
		Content string `json:"content"`
	}
	if json.Unmarshal(output, &object) == nil && object.Content != "" {
		return object.Content
	}
	return string(output)
}

// scanLines calls visit with each line of reader, however long.
func scanLines(reader io.Reader, visit func([]byte)) {
	buffered := bufio.NewReader(reader)
	for {
		line, err := buffered.ReadBytes('\n')
		if trimmed := bytes.TrimSpace(line); len(trimmed) > 0 {
			visit(trimmed)
		}
		if err != nil {
			return
		}
	}
}
