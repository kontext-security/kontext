package tooloutput

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/modelusage"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

const (
	historyItems = 6
	// maxContextText bounds the goal and the assistant text, and
	// maxHistoryText each history item, so the context never crowds the
	// output out of a request.
	maxContextText = 16 << 10
	maxHistoryText = 64 << 10
	// maxRedacted bounds the context text one request redacts, the call's
	// own input aside (see redactions).
	maxRedacted = 2 << 20
)

// transcriptTail is how much of a transcript's end is read for context. A
// variable so tests can make a transcript longer than it cheaply.
var transcriptTail int64 = 2 << 20

// requestContext builds what the server is told about the call: the person's
// latest prompt, what the assistant said with this call, and the visible
// transcript items before it. goal is the prompt the hooks last reported.
// The transcript is read for the rest, and for the model. History leaves out
// every call withheld (with its result).
func requestContext(event hook.Event, goal, home string, withheld func(input any) bool) (Context, *string) {
	path, subagent := event.TranscriptPath, false
	if event.AgentTranscriptPath != "" {
		// A subagent's own transcript; its task is the goal it works on.
		path, subagent = event.AgentTranscriptPath, true
	}
	conversation, whole := readConversation(event.Agent, path, subagent, home)
	if subagent || goal == "" {
		if latest := latestUserText(conversation.Messages, !subagent); latest != "" {
			goal = latest
		}
	}
	context := conversationContext(conversation, whole, goal, event.ToolUseID, event.ToolName, event.ToolInput, withheld)
	if conversation.Model == "" {
		return context, nil
	}
	return context, &conversation.Model
}

// conversationContext is what the server is told about the call toolUseID of
// conversation, its secrets redacted; whole reports that conversation starts
// where the conversation does.
func conversationContext(conversation modelusage.Conversation, whole bool, goal, toolUseID, toolName string, toolInput any, withheld func(input any) bool) Context {
	assistantText, before := splitCurrent(conversation.Messages, toolUseID)
	// The goal has the first claim on the budget, then what the assistant
	// said with the call, then the history.
	budget := &redactions{left: maxRedacted}
	goal = budget.text(goal, maxContextText)
	assistantText = budget.text(assistantText, maxContextText)
	items, length := history(before, withheld, budget)
	context := Context{
		Goal: goal,
		Current: Current{
			AssistantText: assistantText,
			ToolName:      toolName,
			ToolInput:     redactedInput(toolInput),
		},
		History: items,
	}
	// The count is right only when the read reached the start of what the
	// model sees: the transcript's start or its latest compaction.
	if whole || conversation.Compacted {
		context.HistoryLength = &length
	}
	return context
}

// readConversation reads the end of an agent's transcript, and reports
// whether that was all of it. A transcript it cannot read gives no context,
// and neither does one in a folder macOS guards (see readTail).
func readConversation(agent, path string, subagent bool, home string) (conversation modelusage.Conversation, whole bool) {
	readTail(path, home, func(tail io.Reader, all bool) {
		if agent == "codex" {
			conversation = modelusage.ReadCodexConversation(tail)
		} else {
			conversation = modelusage.ReadClaudeConversation(tail, subagent)
		}
		whole = all
	})
	return conversation, whole
}

// codexExitCode reads the end of a Codex call's session log for the exit code
// of its command (see modelusage.CodexCommandExit). A log it cannot read
// tells it nothing.
func codexExitCode(event hook.Event, home string) (code int, finished bool) {
	readTail(event.TranscriptPath, home, func(tail io.Reader, _ bool) {
		code, finished = modelusage.CodexCommandExit(tail, event.ToolUseID)
	})
	return code, finished
}

// readTail calls read with the end of a transcript, from the first whole
// line of its last transcriptTail bytes, and whether that is all of it. It
// never opens a transcript in a folder macOS guards, and does not call read
// for one it cannot open.
func readTail(path, home string, read func(tail io.Reader, whole bool)) {
	if path == "" || privacyfolder.Guarded(home, path) {
		return
	}
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	var reader io.Reader = file
	offset := info.Size() - transcriptTail
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return
		}
		// Start at the first whole line.
		buffered := bufio.NewReader(io.LimitReader(file, transcriptTail))
		if _, err := buffered.ReadBytes('\n'); err != nil {
			return
		}
		reader = buffered
	}
	read(reader, offset <= 0)
}

// latestUserText is the last text a person sent, or with prompts set, the
// last that started a turn.
func latestUserText(messages []modelusage.Message, prompts bool) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" && (messages[i].Prompt || !prompts) {
			return messages[i].Text
		}
	}
	return ""
}

// splitCurrent finds the response that issued the call and returns its text
// and everything before it. A transcript not yet showing the call (they lag
// behind hooks) ends with the response in progress, if any.
func splitCurrent(messages []modelusage.Message, toolUseID string) (string, []modelusage.Message) {
	call := slices.IndexFunc(messages, func(message modelusage.Message) bool {
		return toolUseID != "" && message.ToolCall != nil && message.ToolCall.ID == toolUseID
	})
	same := func(i int) bool {
		return messages[i].Role == "assistant" && (call < 0 || messages[i].Response == messages[call].Response)
	}
	start, end := len(messages), len(messages)
	if call >= 0 {
		start, end = call, call+1
		for end < len(messages) && same(end) {
			end++
		}
	}
	for start > 0 && same(start-1) {
		start--
	}
	var texts []string
	for _, message := range messages[start:end] {
		if message.Text != "" {
			texts = append(texts, message.Text)
		}
	}
	return strings.Join(texts, "\n"), messages[:start]
}

// history is the last visible items before the current call, and how many
// there are in all. Every call withheld reports is left out with its result,
// and so is a result whose call is no longer in view, which cannot be
// checked. The items' texts are redacted within budget, newest first.
func history(messages []modelusage.Message, withheld func(input any) bool, budget *redactions) ([]HistoryItem, int) {
	calls := map[string]*modelusage.ToolCall{}
	for _, message := range messages {
		if message.ToolCall != nil {
			calls[message.ToolCall.ID] = message.ToolCall
		}
	}
	verdicts := map[string]bool{}
	private := func(call *modelusage.ToolCall) bool {
		if call == nil {
			return true
		}
		verdict, known := verdicts[call.ID]
		if !known {
			var input any
			if json.Unmarshal(call.Input, &input) != nil {
				input = string(call.Input)
			}
			verdict = withheld != nil && withheld(input)
			verdicts[call.ID] = verdict
		}
		return verdict
	}
	var visible []modelusage.Message
	for _, message := range messages {
		if message.ToolCall != nil && private(message.ToolCall) || message.Role == "tool" && private(calls[message.ToolUseID]) {
			continue
		}
		visible = append(visible, message)
	}
	kept := visible[max(len(visible)-historyItems, 0):]
	items := make([]HistoryItem, len(kept))
	for i := len(kept) - 1; i >= 0; i-- {
		message := kept[i]
		item := HistoryItem{Role: message.Role, Content: budget.text(message.Text, maxHistoryText), ToolUseID: message.ToolUseID}
		if call := message.ToolCall; call != nil {
			item.ToolCalls = []ToolCall{{ID: call.ID, Name: call.Name, Input: budget.input(call.Input, maxHistoryText)}}
		}
		items[i] = item
	}
	return items, len(visible)
}

// leftOut stands in for a context text past the redaction budget.
const leftOut = "[...]"

// redactions is what is left of a request's budget for redacting context.
// Redaction reads all of a text, and clipping a text before redacting it
// could leave part of a secret the ruleset would no longer recognize, so a
// text larger than what is left is left out instead. The call's own input
// is redacted whole: it is small, and the server needs it.
type redactions struct {
	left int
}

// text returns text redacted, then clipped to limit, or leftOut.
func (r *redactions) text(text string, limit int) string {
	if !r.spend(len(text)) {
		return leftOut
	}
	return clip(redacted(text), limit)
}

// input returns a tool call's input redacted, then, when longer than limit,
// clipped as text into a JSON string; or leftOut as one.
func (r *redactions) input(raw json.RawMessage, limit int) json.RawMessage {
	if !r.spend(len(raw)) {
		data, _ := json.Marshal(leftOut)
		return data
	}
	input := redactedJSON(raw)
	if len(input) > limit {
		input, _ = json.Marshal(clip(string(input), limit))
	}
	return input
}

func (r *redactions) spend(n int) bool {
	if n > r.left {
		return false
	}
	r.left -= n
	return true
}

// clip shortens text over limit bytes to its start and end.
func clip(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	const marker = "\n[...]\n"
	head := (limit - len(marker)) / 2
	tail := len(text) - (limit - len(marker) - head)
	for head > 0 && !utf8.RuneStart(text[head]) {
		head--
	}
	for tail < len(text) && !utf8.RuneStart(text[tail]) {
		tail++
	}
	return text[:head] + marker + text[tail:]
}
