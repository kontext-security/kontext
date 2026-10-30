package tooloutput

import (
	"encoding/json"
	"maps"
	"strconv"
	"strings"

	"github.com/kontext-security/kontext/internal/hook"
)

// minOutputBytes is the smallest output worth sending: anything at or below
// it stays as it is.
const minOutputBytes = 2048

// output is a tool result's text that compaction may shorten, and how to put
// a shortened text back into the tool response.
type output struct {
	kind      string
	text      string
	filePath  string
	startLine int
	rebuild   func(text string) map[string]any
}

// LiveCandidate reports whether a PostToolUse carries an output live
// compaction handles: a Claude Code Bash stdout or Read text over 2048 bytes.
// The hook asks the daemon only about these, so every other call costs
// nothing extra.
func LiveCandidate(event hook.Event) bool {
	_, ok := liveOutput(event)
	return ok
}

func liveOutput(event hook.Event) (output, bool) {
	if event.Agent != "claude" || event.HookName != hook.HookPostToolUse {
		return output{}, false
	}
	response := event.ToolResponse
	switch event.ToolName {
	case "Bash":
		// Claude Code already moves a long stdout to a file of its own
		// (persistedOutputPath) and shows a preview; that stays its business.
		stdout, ok := response["stdout"].(string)
		if !ok || len(stdout) <= minOutputBytes || present(response["persistedOutputPath"]) || response["isImage"] == true {
			return output{}, false
		}
		return output{kind: KindText, text: stdout, rebuild: func(text string) map[string]any {
			rebuilt := maps.Clone(response)
			rebuilt["stdout"] = text
			return rebuilt
		}}, true
	case "Read":
		file, _ := response["file"].(map[string]any)
		content, isText := file["content"].(string)
		path, _ := file["filePath"].(string)
		start, numbered := lineNumber(file["startLine"])
		if response["type"] != "text" || !isText || path == "" || !numbered || len(content) <= minOutputBytes {
			return output{}, false
		}
		return output{kind: KindFileLines, text: content, filePath: path, startLine: start, rebuild: func(text string) map[string]any {
			rebuiltFile := maps.Clone(file)
			rebuiltFile["content"] = text
			rebuilt := maps.Clone(response)
			rebuilt["file"] = rebuiltFile
			return rebuilt
		}}, true
	}
	return output{}, false
}

// shadowOutput is a Codex shell call's output. Codex reports it as a plain
// string, which the hook adapter keeps under "content".
func shadowOutput(event hook.Event) (output, bool) {
	if event.Agent != "codex" || event.HookName != hook.HookPostToolUse || event.ToolName != "Bash" {
		return output{}, false
	}
	text, ok := event.ToolResponse["content"].(string)
	if !ok {
		text, ok = event.ToolResponse["stdout"].(string)
	}
	if !ok || len(text) <= minOutputBytes {
		return output{}, false
	}
	return output{kind: KindText, text: text}, true
}

// acceptable reports whether a replacement for out can stand in for it: it
// must be shorter, and a Read result must keep its line count so the line
// numbers Claude Code prints stay right.
func (out output) acceptable(text string) bool {
	if len(text) >= len(out.text) {
		return false
	}
	return out.kind != KindFileLines || strings.Count(text, "\n") == strings.Count(out.text, "\n")
}

func present(value any) bool {
	text, isText := value.(string)
	return value != nil && (!isText || text != "")
}

// lineNumber reads a positive line number from decoded JSON.
func lineNumber(value any) (int, bool) {
	var text string
	switch number := value.(type) {
	case json.Number:
		text = number.String()
	case float64:
		text = strconv.FormatFloat(number, 'f', -1, 64)
	case int:
		text = strconv.Itoa(number)
	default:
		return 0, false
	}
	line, err := strconv.Atoi(text)
	return line, err == nil && line > 0
}

// omittedLines returns the file line ranges a Read replacement left out, both
// ends included, numbered from first. The replacement keeps the line count:
// every line it changed was left out, and so were the blank lines padding a
// changed one, which is how an omitted run keeps its length. A blank line
// kept right after a run reads as part of it.
func omittedLines(original, replaced string, first int) [][2]int {
	before, after := strings.Split(original, "\n"), strings.Split(replaced, "\n")
	if len(before) != len(after) {
		return nil
	}
	if strings.HasSuffix(original, "\n") {
		// The empty string after the final newline is no line of the file.
		before, after = before[:len(before)-1], after[:len(after)-1]
	}
	var ranges [][2]int
	run := -1
	for i := range before {
		if before[i] != after[i] || run >= 0 && after[i] == "" {
			if run < 0 {
				run = i
			}
			continue
		}
		if run >= 0 {
			ranges = append(ranges, [2]int{first + run, first + i - 1})
			run = -1
		}
	}
	if run >= 0 {
		ranges = append(ranges, [2]int{first + run, first + len(before) - 1})
	}
	return ranges
}
