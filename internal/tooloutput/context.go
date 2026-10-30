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
)

// transcriptTail is how much of a transcript's end is read for context. A
// variable so tests can make a transcript longer than it cheaply.
var transcriptTail int64 = 2 << 20

// requestContext builds what the server is told about the call: the person's
// latest prompt, what the assistant said with this call, and the visible
// transcript items before it. goal is the prompt the hooks last reported.
// The transcript is read for the rest, and for the model. History leaves out
// every call withheld (with its result), as well as calls touching a privacy
// folder.
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
	assistantText, before := splitCurrent(conversation.Messages, event.ToolUseID)
	items, length := history(before, home, event.CWD, withheld)
	context := Context{
		Goal: clip(goal, maxContextText),
		Current: Current{
			AssistantText: clip(assistantText, maxContextText),
			ToolName:      event.ToolName,
			ToolInput:     event.ToolInput,
		},
		History: items,
	}
	// The count is right only when the read reached the start of what the
	// model sees: the transcript's start or its latest compaction.
	if whole || conversation.Compacted {
		context.HistoryLength = &length
	}
	if conversation.Model == "" {
		return context, nil
	}
	return context, &conversation.Model
}

// readConversation reads the end of an agent's transcript, and reports
// whether that was all of it. A transcript it cannot read, or one in a privacy
// folder, gives no context.
func readConversation(agent, path string, subagent bool, home string) (modelusage.Conversation, bool) {
	if path == "" || privacyfolder.Guarded(home, path) {
		return modelusage.Conversation{}, false
	}
	file, err := os.Open(path)
	if err != nil {
		return modelusage.Conversation{}, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return modelusage.Conversation{}, false
	}
	var reader io.Reader = file
	offset := info.Size() - transcriptTail
	if offset > 0 {
		if _, err := file.Seek(offset, io.SeekStart); err != nil {
			return modelusage.Conversation{}, false
		}
		// Start at the first whole line.
		buffered := bufio.NewReader(io.LimitReader(file, transcriptTail))
		if _, err := buffered.ReadBytes('\n'); err != nil {
			return modelusage.Conversation{}, false
		}
		reader = buffered
	}
	if agent == "codex" {
		return modelusage.ReadCodexConversation(reader), offset <= 0
	}
	return modelusage.ReadClaudeConversation(reader, subagent), offset <= 0
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
// there are in all. Every call that touches a privacy folder, or that withheld
// reports, is left out with its result, and so is a result whose call is no
// longer in view, which cannot be checked.
func history(messages []modelusage.Message, home, cwd string, withheld func(input any) bool) ([]HistoryItem, int) {
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
			verdict = withheld != nil && withheld(input) || touchesPrivacyFolder(home, cwd, input)
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
	items := make([]HistoryItem, 0, len(kept))
	for _, message := range kept {
		item := HistoryItem{Role: message.Role, Content: clip(message.Text, maxHistoryText), ToolUseID: message.ToolUseID}
		if call := message.ToolCall; call != nil {
			input := call.Input
			if len(input) > maxHistoryText {
				input, _ = json.Marshal(clip(string(input), maxHistoryText))
			}
			item.ToolCalls = []ToolCall{{ID: call.ID, Name: call.Name, Input: input}}
		}
		items = append(items, item)
	}
	return items, len(visible)
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
