package tooloutput

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

func TestOmittedLines(t *testing.T) {
	original := "a\nb\nc\n\nd\ne\nf\n"
	tests := []struct {
		name     string
		replaced string
		first    int
		want     [][2]int
	}{
		{name: "unchanged", replaced: original, first: 1},
		{name: "middle run padded with blank lines", replaced: "a\n[cut 2-4]\n\n\nd\ne\nf\n", first: 1, want: [][2]int{{2, 4}}},
		{name: "numbered from the read's first line", replaced: "a\n[cut]\n\n\nd\ne\nf\n", first: 101, want: [][2]int{{102, 104}}},
		{name: "two runs", replaced: "[cut]\nb\nc\n\nd\n[cut]\n\n", first: 1, want: [][2]int{{1, 1}, {6, 7}}},
		{name: "run to the end", replaced: "a\nb\nc\n\n[cut]\n\n\n", first: 1, want: [][2]int{{5, 7}}},
		{name: "line count changed", replaced: "a\n[cut]\nf\n", first: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := omittedLines(original, test.replaced, test.first); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("omittedLines() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestLiveCandidates(t *testing.T) {
	long := strings.Repeat("x", minOutputBytes+1)
	bash := func(response map[string]any) hook.Event {
		return hook.Event{Agent: "claude", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolResponse: response}
	}
	read := func(file map[string]any) hook.Event {
		return hook.Event{Agent: "claude", HookName: hook.HookPostToolUse, ToolName: "Read", ToolResponse: map[string]any{"type": "text", "file": file}}
	}
	tests := []struct {
		name  string
		event hook.Event
		want  bool
	}{
		{name: "bash", event: bash(map[string]any{"stdout": long}), want: true},
		// 2048 bytes is the bar, in UTF-8: 683 three-byte runes are 2049 bytes.
		{name: "bash multibyte", event: bash(map[string]any{"stdout": strings.Repeat("€", 683)}), want: true},
		{name: "bash at the bar", event: bash(map[string]any{"stdout": strings.Repeat("x", minOutputBytes)})},
		{name: "bash persisted", event: bash(map[string]any{"stdout": long, "persistedOutputPath": "/tmp/out.txt"})},
		{name: "bash empty persisted path", event: bash(map[string]any{"stdout": long, "persistedOutputPath": ""}), want: true},
		{name: "bash image", event: bash(map[string]any{"stdout": long, "isImage": true})},
		{name: "read", event: read(map[string]any{"content": long, "filePath": "/repo/a.go", "startLine": json.Number("1")}), want: true},
		{name: "read float line", event: read(map[string]any{"content": long, "filePath": "/repo/a.go", "startLine": 7.0}), want: true},
		{name: "read without start line", event: read(map[string]any{"content": long, "filePath": "/repo/a.go"})},
		{name: "read image", event: hook.Event{Agent: "claude", HookName: hook.HookPostToolUse, ToolName: "Read",
			ToolResponse: map[string]any{"type": "image", "file": map[string]any{"content": long, "filePath": "/a.png", "startLine": json.Number("1")}}}},
		{name: "other tool", event: hook.Event{Agent: "claude", HookName: hook.HookPostToolUse, ToolName: "Grep", ToolResponse: map[string]any{"stdout": long}}},
		{name: "pre tool use", event: hook.Event{Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolResponse: map[string]any{"stdout": long}}},
		{name: "cowork", event: hook.Event{Agent: "cowork", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolResponse: map[string]any{"stdout": long}}},
		{name: "codex", event: hook.Event{Agent: "codex", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolUseID: "call_1",
			ToolResponse: map[string]any{"content": long}}, want: true},
		{name: "codex small", event: hook.Event{Agent: "codex", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolUseID: "call_1",
			ToolResponse: map[string]any{"content": "ok"}}},
		{name: "codex code mode", event: hook.Event{Agent: "codex", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolUseID: "exec-0b3c",
			ToolResponse: map[string]any{"content": long}}},
		{name: "codex structured", event: hook.Event{Agent: "codex", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolUseID: "call_1",
			ToolResponse: map[string]any{"stdout": long}}},
		{name: "codex other tool", event: hook.Event{Agent: "codex", HookName: hook.HookPostToolUse, ToolName: "apply_patch", ToolUseID: "call_1",
			ToolResponse: map[string]any{"content": long}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := LiveCandidate(test.event); got != test.want {
				t.Fatalf("LiveCandidate() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestEachWord(t *testing.T) {
	var got []string
	eachWord(`cat "a b/c" 'd e' f\ g|grep -n x>out;ls $HOME/x&&echo "it's" '$lit'`, func(word string) bool {
		got = append(got, word)
		return true
	})
	want := []string{"cat", "a b/c", "d e", "f g", "grep", "-n", "x", "out", "ls", "$HOME/x", "echo", "it's", "$lit"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("eachWord() = %q, want %q", got, want)
	}
	got = nil
	eachWord("a b c d", func(word string) bool {
		got = append(got, word)
		return len(got) < 2
	})
	if !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("eachWord() after stopping = %q", got)
	}
}

func TestResolvePath(t *testing.T) {
	for word, want := range map[string]string{
		"~/Documents/a":     "/home/u/Documents/a",
		"$HOME/Desktop":     "/home/u/Desktop",
		"${HOME}/Downloads": "/home/u/Downloads",
		"/etc/hosts":        "/etc/hosts",
		"../Documents/x":    "/home/u/Documents/x",
		"-la":               "",
		"":                  "",
	} {
		if got := resolvePath("/home/u", "/home/u/code", word); got != want {
			t.Errorf("resolvePath(%q) = %q, want %q", word, got, want)
		}
	}
}
