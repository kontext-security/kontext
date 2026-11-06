package hookruntime

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
)

// The payloads in testdata/antigravity were captured from Antigravity 2.29.0
// with a logging hook on a real agent loop, then stripped of personal paths and
// prompts. What the app does with each answer was measured the same way, since
// Google's documentation is wrong or silent on most of it.
//
// Ways the adapter can fail, each pinned below:
//   - "{}" or an empty decision reaches Antigravity, which reads both as a deny,
//     so every tool call in the app is blocked
//   - an answer skips the person's approval prompt (auto_approve does)
//   - a run_command keeps its name and CommandLine, so shell policies and risk
//     rules see no shell at all and silently allow it
//   - a file tool keeps Path or AbsolutePath, so a rule on .env never matches
//   - an MCP call stays call_mcp_tool and loses its server, so MCP policies and
//     the Resources tab miss it
//   - the two events of one call get different ids, so its outcome is lost
//   - a failed tool is recorded as a success
//   - every model call mints a turn, or a sub-agent mints one with no prompt
//   - a payload Kontext cannot read blocks the agent instead of passing
func TestDecodeAntigravityEventCapturedPayloads(t *testing.T) {
	t.Parallel()

	const conversation = "113d28c3-9ac2-4d13-9708-1a9c0bc268ce"
	const session = "antigravity-" + conversation
	cases := []struct {
		file                                 string
		alias, want                          hook.HookName
		toolName, toolUseID, inputKey, want2 string
	}{
		{file: "session-start", alias: hook.HookSessionStart, want: hook.HookSessionStart},
		{file: "pre-invocation-first", alias: hook.HookUserPromptSubmit, want: hook.HookUserPromptSubmit, inputKey: "prompt", want2: "Fix the failing test in the probe project"},
		{file: "pre-tool-use-run-command", alias: hook.HookPreToolUse, want: hook.HookPreToolUse, toolName: "Bash", toolUseID: "agy-" + conversation + "-8", inputKey: "command", want2: `grep -rn "beta" /Users/dev/agy-probe`},
		{file: "pre-tool-use-read-file", alias: hook.HookPreToolUse, want: hook.HookPreToolUse, toolName: "Read", toolUseID: "agy-" + conversation + "-4", inputKey: "file_path", want2: "/Users/dev/agy-probe/h.txt"},
		{file: "pre-tool-use-write-file", alias: hook.HookPreToolUse, want: hook.HookPreToolUse, toolName: "Write", toolUseID: "agy-" + conversation + "-2", inputKey: "file_path", want2: "/Users/dev/agy-probe/h.txt"},
		{file: "pre-tool-use-edit-file", alias: hook.HookPreToolUse, want: hook.HookPreToolUse, toolName: "Edit", toolUseID: "agy-" + conversation + "-6", inputKey: "new_string", want2: "beta"},
		{file: "pre-tool-use-call-mcp-tool", alias: hook.HookPreToolUse, want: hook.HookPreToolUse, toolName: "mcp__spikelazy__echo_tool", toolUseID: "agy-" + conversation + "-14", inputKey: "text", want2: "lazy"},
		{file: "pre-tool-use-invoke-subagent", alias: hook.HookPreToolUse, want: hook.HookPreToolUse, toolName: "Task", toolUseID: "agy-" + conversation + "-18", inputKey: "subagent_type", want2: "self"},
		{file: "post-tool-use-run-command", alias: hook.HookPostToolUse, want: hook.HookPostToolUse, toolName: "Bash", toolUseID: "agy-" + conversation + "-8", inputKey: "command", want2: `grep -rn "beta" /Users/dev/agy-probe`},
		{file: "stop", alias: hook.HookStop, want: hook.HookStop},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			t.Parallel()
			event, err := DecodeAntigravityEvent(readAntigravityFixture(t, tc.file), "antigravity", tc.alias)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if event.HookName != tc.want || event.SessionID != session || event.Agent != "antigravity" {
				t.Fatalf("event = %s %s %s", event.HookName, event.SessionID, event.Agent)
			}
			if event.ToolName != tc.toolName || event.ToolUseID != tc.toolUseID {
				t.Fatalf("tool = %q %q, want %q %q", event.ToolName, event.ToolUseID, tc.toolName, tc.toolUseID)
			}
			if tc.inputKey != "" && event.ToolInput[tc.inputKey] != tc.want2 {
				t.Fatalf("input[%s] = %#v, want %q; input %#v", tc.inputKey, event.ToolInput[tc.inputKey], tc.want2, event.ToolInput)
			}
			if event.CWD != "/Users/dev/agy-probe" {
				t.Fatalf("cwd = %q", event.CWD)
			}
			if !strings.HasSuffix(event.TranscriptPath, "transcript_full.jsonl") || event.Model != "gemini-3.5-flash-lite" {
				t.Fatalf("transcript %q model %q", event.TranscriptPath, event.Model)
			}
		})
	}
}

func TestDecodeAntigravityEventPairsToolEventsAndCarriesFailure(t *testing.T) {
	t.Parallel()
	pre, err := DecodeAntigravityEvent(readAntigravityFixture(t, "pre-tool-use-run-command"), "antigravity", hook.HookPreToolUse)
	if err != nil {
		t.Fatal(err)
	}
	post, err := DecodeAntigravityEvent(readAntigravityFixture(t, "post-tool-use-run-command"), "antigravity", hook.HookPostToolUse)
	if err != nil {
		t.Fatal(err)
	}
	if pre.ToolUseID == "" || pre.ToolUseID != post.ToolUseID {
		t.Fatalf("pre %q post %q must share an id", pre.ToolUseID, post.ToolUseID)
	}
	if post.Error != "" {
		t.Fatalf("a call without an error is a success, got %q", post.Error)
	}
	failed, err := DecodeAntigravityEvent(readAntigravityFixture(t, "post-tool-use-failed-read-file"), "antigravity", hook.HookPostToolUse)
	if err != nil {
		t.Fatal(err)
	}
	if failed.HookName != hook.HookPostToolUseFailed || failed.Error != "file does not exist" || failed.ToolName != "Read" {
		t.Fatalf("failed call = %s %q %q", failed.HookName, failed.Error, failed.ToolName)
	}
}

func TestDecodeAntigravityEventMintsTurnsOnlyForPersonPrompts(t *testing.T) {
	t.Parallel()
	if _, err := DecodeAntigravityEvent(readAntigravityFixture(t, "pre-invocation-later"), "antigravity", hook.HookUserPromptSubmit); err == nil {
		t.Fatal("a later model call in the same turn must not mint a turn")
	}
	// A sub-agent's first model call names no person's prompt.
	subagent := bytes.Replace(readAntigravityFixture(t, "pre-invocation-first"), []byte("Fix the failing test in the probe project"), nil, 1)
	if _, err := DecodeAntigravityEvent(subagent, "antigravity", hook.HookUserPromptSubmit); err == nil {
		t.Fatal("a model call with no person's prompt must not mint a turn")
	}
	start, err := DecodeAntigravityEvent(readAntigravityFixture(t, "session-start-subagent"), "antigravity", hook.HookSessionStart)
	if err != nil {
		t.Fatal(err)
	}
	if start.SessionID != "antigravity-0422b3f6-7872-40e8-a4d7-9ff4e231c73b" || start.CWD != "" {
		t.Fatalf("sub-agent session = %q cwd %q", start.SessionID, start.CWD)
	}
}

// The argument names differ between models and app versions: these spellings
// come from Google's tool list and from transcripts of the app's default model.
func TestDecodeAntigravityEventCanonicalizesEveryToolSpelling(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, args, tool, key, value string
	}{
		{"view_file", `{"AbsolutePath":"/p/.env","StartLine":1}`, "Read", "file_path", "/p/.env"},
		{"read_file", `{"Path":"/p/.env"}`, "Read", "file_path", "/p/.env"},
		{"write_to_file", `{"TargetFile":"/p/a","CodeContent":"x"}`, "Write", "content", "x"},
		{"write_file", `{"Path":"/p/a","Content":"x"}`, "Write", "content", "x"},
		{"replace_file_content", `{"TargetFile":"/p/a","TargetContent":"x","ReplacementContent":"y"}`, "Edit", "old_string", "x"},
		{"multi_replace_file_content", `{"TargetFile":"/p/a"}`, "MultiEdit", "file_path", "/p/a"},
		{"run_command", `{"CommandLine":"ls","toolSummary":"List"}`, "Bash", "description", "List"},
		{"list_dir", `{"DirectoryPath":"/p"}`, "LS", "path", "/p"},
		{"find_by_name", `{"SearchDirectory":"/p","Pattern":"*.go"}`, "Glob", "pattern", "*.go"},
		{"grep_search", `{"SearchPath":"/p","Query":"x"}`, "Grep", "pattern", "x"},
		{"search_web", `{"query":"x"}`, "WebSearch", "query", "x"},
		{"read_url_content", `{"Url":"https://example.com"}`, "WebFetch", "url", "https://example.com"},
		{"send_message", `{"Message":"x"}`, "send_message", "Message", "x"},
	}
	for _, tc := range cases {
		input := []byte(`{"conversationId":"c1","stepIdx":3,"toolCall":{"name":"` + tc.name + `","args":` + tc.args + `}}`)
		event, err := DecodeAntigravityEvent(input, "antigravity", hook.HookPreToolUse)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if event.ToolName != tc.tool || event.ToolInput[tc.key] != tc.value {
			t.Errorf("%s = %s %#v, want %s %s=%s", tc.name, event.ToolName, event.ToolInput, tc.tool, tc.key, tc.value)
		}
	}
	// A command's own directory says where it runs, ahead of the workspace.
	input := []byte(`{"conversationId":"c1","workspacePaths":["/w"],"toolCall":{"name":"run_command","args":{"CommandLine":"ls","Cwd":"/w/sub"}}}`)
	event, err := DecodeAntigravityEvent(input, "antigravity", hook.HookPreToolUse)
	if err != nil {
		t.Fatal(err)
	}
	if event.CWD != "/w/sub" || event.ToolInput["cwd"] != "/w/sub" {
		t.Fatalf("cwd = %q input %#v", event.CWD, event.ToolInput)
	}
}

func TestDecodeAntigravityEventRejectsWhatItCannotRead(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, input string
		alias       hook.HookName
	}{
		{"not json", `not json`, hook.HookPreToolUse},
		{"no conversation", `{"toolCall":{"name":"run_command","args":{}}}`, hook.HookPreToolUse},
		{"no tool call", `{"conversationId":"c1"}`, hook.HookPreToolUse},
		{"post with null tool call", `{"conversationId":"c1","toolCall":null}`, hook.HookPostToolUse},
		{"mcp call without a server", `{"conversationId":"c1","toolCall":{"name":"call_mcp_tool","args":{"ToolName":"x"}}}`, hook.HookPreToolUse},
		{"no event in the hook command", `{"conversationId":"c1"}`, ""},
		{"an event this agent never sends", `{"conversationId":"c1"}`, hook.HookSessionEnd},
	}
	for _, tc := range cases {
		if _, err := DecodeAntigravityEvent([]byte(tc.input), "antigravity", tc.alias); err == nil {
			t.Errorf("%s: want an error", tc.name)
		}
	}
}

func TestEncodeAntigravityResult(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		hook   hook.HookName
		result hook.Result
		want   string
	}{
		// allow keeps the person's approval prompt; measured with
		// AGENT_PERMISSION_PRESET_REQUEST_REVIEW. auto_approve would skip it.
		{"allow", hook.HookPreToolUse, hook.Result{Decision: hook.DecisionAllow}, `{"decision":"allow"}`},
		{"failed open", hook.HookPreToolUse, hook.Result{Decision: hook.DecisionDeny, FailedOpen: true}, `{"decision":"allow"}`},
		{"deny", hook.HookPreToolUse, hook.Result{Decision: hook.DecisionDeny, Reason: "Blocked by policy"}, `{"decision":"deny","reason":"Blocked by policy"}`},
		{"unknown decision blocks", hook.HookPreToolUse, hook.Result{Decision: hook.Decision("later"), Reason: "x"}, `{"decision":"deny","reason":"x"}`},
		{"post", hook.HookPostToolUse, hook.Result{Decision: hook.DecisionDeny, Reason: "x"}, `{}`},
		{"prompt", hook.HookUserPromptSubmit, hook.Result{Decision: hook.DecisionAllow}, `{}`},
		{"stop", hook.HookStop, hook.Result{Decision: hook.DecisionAllow}, `{}`},
		{"session", hook.HookSessionStart, hook.Result{Decision: hook.DecisionAllow}, `{}`},
	}
	for _, tc := range cases {
		out, err := EncodeAntigravityResult(tc.hook, tc.result)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if string(out) != tc.want {
			t.Errorf("%s = %s, want %s", tc.name, out, tc.want)
		}
		if bytes.Contains(out, []byte("auto_approve")) {
			t.Errorf("%s: auto_approve skips the person's approval prompt", tc.name)
		}
	}
	var answer map[string]string
	if err := json.Unmarshal(AntigravityNoDecision(), &answer); err != nil || answer["decision"] != "allow" {
		t.Fatalf("no decision = %s, %v", AntigravityNoDecision(), err)
	}
}

type antigravityTestCodec struct{ alias hook.HookName }

func (c antigravityTestCodec) DecodeHookEvent(input []byte) (hook.Event, error) {
	return DecodeAntigravityEvent(input, "antigravity", c.alias)
}

func (c antigravityTestCodec) EncodeHookResult(event hook.Event, result hook.Result) ([]byte, error) {
	return EncodeAntigravityResult(event.HookName, result)
}

func (antigravityTestCodec) NoDecision() []byte { return AntigravityNoDecision() }

// Antigravity reads "{}" from PreToolUse as a deny, so a decode failure has to
// print the neutral answer rather than Cursor's.
func TestRunPassesWhenAntigravityPayloadCannotBeRead(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := Run(strings.NewReader(`not json`), &stdout, &stderr, antigravityTestCodec{alias: hook.HookPreToolUse}, func(hook.Event) (hook.Result, error) {
		t.Fatal("must not evaluate")
		return hook.Result{}, nil
	})
	if code != 0 || stdout.String() != `{"decision":"allow"}` {
		t.Fatalf("code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
}

func readAntigravityFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "antigravity", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Only a shell call runs where its arguments say. An MCP tool's arguments are its
// own data, and the MCP config lookup reads event.CWD: a call must not be able to
// pick the workspace whose config identifies it for policy.
func TestDecodeAntigravityEventTakesADirectoryOnlyFromAShellCall(t *testing.T) {
	t.Parallel()
	for _, call := range []string{
		`{"name":"call_mcp_tool","args":{"ServerName":"github","ToolName":"list","Arguments":{"cwd":"/other/project"}}}`,
		`{"name":"read_file","args":{"Path":"/w/a","cwd":"/other/project"}}`,
		`{"name":"some_new_tool","args":{"cwd":"/other/project"}}`,
	} {
		input := []byte(`{"conversationId":"c1","workspacePaths":["/w"],"toolCall":` + call + `}`)
		event, err := DecodeAntigravityEvent(input, "antigravity", hook.HookPreToolUse)
		if err != nil {
			t.Fatal(err)
		}
		if event.CWD != "/w" {
			t.Errorf("%s moved the call to %q", call, event.CWD)
		}
		if event.ToolInput["cwd"] != "/other/project" {
			t.Errorf("%s lost its own argument: %#v", call, event.ToolInput)
		}
	}
}
