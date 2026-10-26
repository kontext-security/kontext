package hookruntime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

// The payloads in testdata/cursor were captured from Cursor 2026.10.22 with a
// logging hook in the enterprise hooks.json, then stripped of personal paths.
// Ways the adapter can fail, each pinned below:
//   - an MCP call is decided twice (preToolUse "MCP:x" and beforeMCPExecution)
//   - an MCP call loses its server, so MCP policies and the Resources tab miss it
//   - Cursor's empty cwd leaves the call without a project
//   - an event Kontext does not handle blocks the agent instead of passing
//   - a deny is encoded in a shape Cursor ignores, or an allow approves a call
func TestDecodeCursorEventCapturedPayloads(t *testing.T) {
	t.Parallel()

	const session = "cursor-58ec982e-4a94-4496-937a-e6a05859e461"
	cases := []struct {
		file, hookName, toolName, cwd, inputKey, inputValue string
	}{
		{"session-start", "SessionStart", "", "/Users/dev/cursor-probe-ws", "", ""},
		{"pre-tool-use-shell", "PreToolUse", "Shell", "/Users/dev/cursor-probe-ws", "command", "echo probe-shell-1"},
		{"pre-tool-use-read", "PreToolUse", "Read", "/Users/dev/cursor-probe-ws", "file_path", "/Users/dev/cursor-probe-ws/notes.txt"},
		{"before-mcp-execution", "PreToolUse", "mcp__probe__echo", "/Users/dev/cursor-probe-ws", "text", "probe-mcp-1"},
		{"after-mcp-execution", "PostToolUse", "mcp__probe__echo", "/Users/dev/cursor-probe-ws", "text", "probe-mcp-1"},
		{"post-tool-use-shell", "PostToolUse", "Shell", "/Users/dev/cursor-probe-ws", "command", "echo probe-shell-1"},
		{"post-tool-use-failure-read", "PostToolUseFailure", "Read", "/Users/dev/cursor-probe-ws", "file_path", "/Users/dev/cursor-probe-ws/new.txt"},
		{"session-end", "SessionEnd", "", "/Users/dev/cursor-probe-ws", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			event, err := DecodeCursorEvent(readCursorPayload(t, tc.file), "cursor")
			if err != nil {
				t.Fatalf("DecodeCursorEvent() error = %v", err)
			}
			if event.Agent != "cursor" || event.SessionID != session || event.HookName.String() != tc.hookName ||
				event.ToolName != tc.toolName || event.CWD != tc.cwd {
				t.Fatalf("event = %+v", event)
			}
			if event.ToolInput == nil {
				t.Fatalf("ToolInput is nil, want an object")
			}
			if tc.inputKey != "" && event.ToolInput[tc.inputKey] != tc.inputValue {
				t.Fatalf("ToolInput[%s] = %v, want %q", tc.inputKey, event.ToolInput[tc.inputKey], tc.inputValue)
			}
		})
	}
}

func TestDecodeCursorEventCarriesOutcome(t *testing.T) {
	t.Parallel()

	post, err := DecodeCursorEvent(readCursorPayload(t, "post-tool-use-shell"), "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := post.ToolResponse["exitCode"].(json.Number); code.String() != "0" || post.DurationMs == nil || *post.DurationMs != 3081 {
		t.Fatalf("post = %+v, want exit code and duration", post)
	}
	mcp, err := DecodeCursorEvent(readCursorPayload(t, "after-mcp-execution"), "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mcp.ToolResponse["content"]; !ok || mcp.ToolUseID != "4ed602ba-cb6b-4d91-966b-42e45a8c4587" {
		t.Fatalf("mcp post = %+v, want result content and the pre call's id", mcp)
	}
	failed, err := DecodeCursorEvent(readCursorPayload(t, "post-tool-use-failure-read"), "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if failed.Error == "" || failed.IsInterrupt == nil {
		t.Fatalf("failure = %+v, want error and interrupt flag", failed)
	}
}

func TestDecodeCursorEventSkipsDuplicateMCPEvents(t *testing.T) {
	t.Parallel()

	for _, file := range []string{"pre-tool-use-mcp", "post-tool-use-mcp"} {
		if _, err := DecodeCursorEvent(readCursorPayload(t, file), "cursor"); err == nil {
			t.Fatalf("%s decoded; want it skipped so beforeMCPExecution/afterMCPExecution decide and record the call once", file)
		}
	}
}

func TestDecodeCursorEventPromptAndUnknownEvents(t *testing.T) {
	t.Parallel()

	prompt, err := DecodeCursorEvent([]byte(`{"conversation_id":"c1","hook_event_name":"beforeSubmitPrompt","prompt":"list files","workspace_roots":["/w"]}`), "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if prompt.HookName != hook.HookUserPromptSubmit || prompt.ToolInput["prompt"] != "list files" || prompt.SessionID != "cursor-c1" {
		t.Fatalf("prompt = %+v", prompt)
	}
	for _, input := range []string{
		`{"conversation_id":"c1","hook_event_name":"afterAgentThought","text":"x"}`,
		`{"conversation_id":"c1","hook_event_name":"beforeTabFileRead"}`,
		`{"conversation_id":"c1"}`,
		`not json`,
	} {
		if _, err := DecodeCursorEvent([]byte(input), "cursor"); err == nil {
			t.Fatalf("DecodeCursorEvent(%s) succeeded; want an error the runner turns into exit 0 with no output", input)
		}
	}
}

func TestEncodeCursorResult(t *testing.T) {
	t.Parallel()

	deny, err := EncodeCursorResult(hook.HookPreToolUse, hook.Result{Decision: hook.DecisionDeny, Reason: "Blocked by rule github-read-only"})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := json.Unmarshal(deny, &out); err != nil {
		t.Fatal(err)
	}
	if out["permission"] != "deny" || out["user_message"] != "Blocked by rule github-read-only" || out["agent_message"] != out["user_message"] {
		t.Fatalf("deny = %s", deny)
	}
	// Kontext never approves: an explicit allow would skip Cursor's own
	// approval prompt. Fail-open and non-blocking events say nothing.
	for _, tc := range []struct {
		name   hook.HookName
		result hook.Result
	}{
		{hook.HookPreToolUse, hook.Result{Decision: hook.DecisionAllow}},
		{hook.HookPreToolUse, hook.Result{Decision: hook.DecisionDeny, FailedOpen: true}},
		{hook.HookPostToolUse, hook.Result{Decision: hook.DecisionDeny}},
		{hook.HookUserPromptSubmit, hook.Result{Decision: hook.DecisionDeny}},
		{hook.HookSessionStart, hook.Result{Decision: hook.DecisionAllow}},
	} {
		got, err := EncodeCursorResult(tc.name, tc.result)
		if err != nil || string(got) != "{}" {
			t.Fatalf("EncodeCursorResult(%s, %+v) = %s, %v; want {}", tc.name, tc.result, got, err)
		}
	}
}

func readCursorPayload(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "cursor", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type cursorTestCodec struct{}

func (cursorTestCodec) DecodeHookEvent(input []byte) (hook.Event, error) {
	return DecodeCursorEvent(input, "cursor")
}

func (cursorTestCodec) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return EncodeCursorResult(event.HookName, result)
}

func (cursorTestCodec) NoDecision() []byte { return []byte("{}") }

// A skipped or unreadable event must still print Cursor's no-decision answer:
// with failClosed set, empty stdout blocks the call.
func TestRunPrintsNoDecisionForSkippedCursorEvents(t *testing.T) {
	t.Parallel()

	for _, input := range [][]byte{readCursorPayload(t, "pre-tool-use-mcp"), []byte("not json")} {
		var stdout, stderr strings.Builder
		code := Run(strings.NewReader(string(input)), &stdout, &stderr, cursorTestCodec{}, func(hook.Event) (hook.Result, error) {
			t.Fatal("evaluated a skipped event")
			return hook.Result{}, nil
		})
		if code != 0 || stdout.String() != "{}" {
			t.Fatalf("Run = %d, stdout %q; want 0 and {}", code, stdout.String())
		}
	}
}
