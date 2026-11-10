package tooloutput

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hermetic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/modelusage"
)

// proxyOutput is the second printed part of a code mode call in a model
// request, after the person's prompt and the assistant's words.
func (c testCompactor) proxyOutput(script, printed string) ProxyOutput {
	quote := func(text string) string {
		data, _ := json.Marshal(text)
		return string(data)
	}
	items := []string{
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"fix the failing test"}]}`,
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Running the tests."}]}`,
		`{"type":"custom_tool_call","call_id":"call_1","name":"exec","input":` + quote(script) + `}`,
		`{"type":"custom_tool_call_output","call_id":"call_1","output":[{"type":"input_text","text":"Script completed\nOutput:\n"},` +
			`{"type":"input_text","text":` + quote(printed) + `}]}`,
	}
	raw := make([]json.RawMessage, len(items))
	for i, item := range items {
		raw[i] = json.RawMessage(item)
	}
	return ProxyOutput{SessionID: "codex-019a", CallID: "call_1", Part: 1, ToolName: "exec", ToolInput: script,
		Model: "gpt-6.1-sol", CWD: c.cwd, Text: printed, Conversation: modelusage.CodexItemsConversation(raw), Whole: true}
}

func TestProxiedPartIsReplacedSavedAndDecidedOnce(t *testing.T) {
	hermetic.NotOnWindows(t, "ENG-932", "tool output compaction isn't ported to Windows paths yet")
	c := newTestCompactor(t, replace("2 tests failed: TestA, TestB"))
	out := c.proxyOutput(`text(await tools.exec_command({cmd: "go test ./..."}))`, bigText(80))

	text, ok := c.CompactProxied(context.Background(), out)
	if !ok || text != "2 tests failed: TestA, TestB" {
		t.Fatalf("CompactProxied = %q, %v", text, ok)
	}
	saved := filepath.Join(c.dir, "codex-019a", "call_1-1.txt")
	requests, _, _ := c.api.calls()
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
	request := requests[0]
	if request.Delivery != DeliveryProxy || request.Part != 1 || request.ToolUseID != "call_1" || request.Mode != ModeLive || request.Agent != "codex" ||
		request.ToolName != "exec" || request.Model == nil || *request.Model != "gpt-6.1-sol" {
		t.Fatalf("request = %+v", request)
	}
	// The script goes as the model wrote it, not wrapped in an object.
	if request.ToolInput != out.ToolInput || request.Context.Current.ToolInput != out.ToolInput {
		t.Fatalf("tool input = %#v, current = %#v", request.ToolInput, request.Context.Current.ToolInput)
	}
	if request.Output.Kind != KindText || request.Output.Text != out.Text || request.Output.RecoveryPath != saved {
		t.Fatalf("output = %+v", request.Output)
	}
	if request.Context.Goal != "fix the failing test" || request.Context.Current.AssistantText != "Running the tests." ||
		request.Context.HistoryLength == nil || *request.Context.HistoryLength != 1 {
		t.Fatalf("context = %+v", request.Context)
	}
	data, err := os.ReadFile(saved)
	if err != nil || string(data) != out.Text {
		t.Fatalf("saved output = %d bytes, %v", len(data), err)
	}
	if info, err := os.Stat(saved); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved output mode = %v, %v", info, err)
	}
	if _, err := os.Stat(filepath.Join(c.dir, "codex-019a", "call_1-1.json")); err != nil {
		t.Fatalf("record not saved: %v", err)
	}

	again, ok := c.CompactProxied(context.Background(), out)
	if !ok || again != text {
		t.Fatalf("second ask = %q, %v", again, ok)
	}
	if requests, _, _ := c.api.calls(); len(requests) != 1 {
		t.Fatalf("asking again sent another request (%d)", len(requests))
	}
}

func TestProxiedPartsLeftAsTheyAre(t *testing.T) {
	keep := func(Request) (int, any) {
		return http.StatusOK, map[string]any{"decision": "keep", "eventId": testEventID}
	}
	failing := func(Request) (int, any) { return http.StatusInternalServerError, map[string]any{} }
	longer := func(Request) (int, any) {
		return http.StatusOK, map[string]any{"decision": "replace", "eventId": testEventID, "text": bigText(90)}
	}
	cases := []struct {
		name  string
		reply func(Request) (int, any)
		edit  func(c testCompactor, out *ProxyOutput)
		sends bool
	}{
		{name: "switch off", reply: replace("short"), edit: func(c testCompactor, _ *ProxyOutput) { c.on.Store(false) }},
		{name: "Codex's summary part", reply: replace("short"), edit: func(_ testCompactor, out *ProxyOutput) { out.Part = 0 }},
		{name: "small part", reply: replace("short"), edit: func(_ testCompactor, out *ProxyOutput) { out.Text = "ok\n" }},
		{name: "unsafe call id", reply: replace("short"), edit: func(_ testCompactor, out *ProxyOutput) { out.CallID = "../call" }},
		{name: "script reads a saved output", reply: replace("short"), edit: func(c testCompactor, out *ProxyOutput) {
			out.ToolInput = `text(await tools.exec_command({cmd: "cat ` + filepath.Join(c.dir, "codex-019a", "call_0-1.txt") + `"}))`
		}},
		{name: "server keeps it", reply: keep, sends: true},
		{name: "server fails", reply: failing, sends: true},
		{name: "replacement not shorter", reply: longer, sends: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestCompactor(t, tc.reply)
			out := c.proxyOutput(`text(await tools.exec_command({cmd: "go test ./..."}))`, bigText(80))
			if tc.edit != nil {
				tc.edit(c, &out)
			}
			if text, ok := c.CompactProxied(context.Background(), out); ok {
				t.Fatalf("part replaced with %q", text)
			}
			if requests, _, _ := c.api.calls(); (len(requests) > 0) != tc.sends {
				t.Fatalf("requests = %d", len(requests))
			}
			if _, err := os.Stat(filepath.Join(c.dir, "codex-019a", "call_1-1.txt")); !os.IsNotExist(err) {
				t.Fatalf("a kept part was saved: %v", err)
			}
		})
	}
}

func TestReadBackOfAProxiedPartIsReported(t *testing.T) {
	c := newTestCompactor(t, replace("2 tests failed"))
	out := c.proxyOutput(`text(await tools.exec_command({cmd: "go test ./..."}))`, bigText(80))
	if _, ok := c.CompactProxied(context.Background(), out); !ok {
		t.Fatal("part not replaced")
	}
	saved := filepath.Join(c.dir, "codex-019a", "call_1-1.txt")
	// A restarted daemon knows the part from its saved record.
	restarted := New(Options{Client: c.client, Enabled: c.on.Load, Dir: c.dir, Home: c.home})
	// The script a later code mode call runs reads the part back.
	nested := hook.Event{SessionID: "codex-019a", Agent: "codex", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolUseID: "exec-7",
		CWD: c.cwd, ToolInput: map[string]any{"command": "sed -n 1,40p " + saved}}
	restarted.Observe(context.Background(), nested)
	select {
	case readBack := <-restarted.readBacks:
		if readBack != (ReadBack{SessionID: "codex-019a", EventID: testEventID, ToolUseID: "exec-7"}) {
			t.Fatalf("read-back = %+v", readBack)
		}
	default:
		t.Fatal("the read-back was not reported")
	}
}

func TestProxyGoalSkipsWhatCodexInjects(t *testing.T) {
	messages := []modelusage.Message{
		{Role: "user", Text: "fix the failing test", Prompt: true},
		{Role: "assistant", Text: "On it."},
		{Role: "user", Text: "# AGENTS.md instructions for /work\n\nRun go test.", Prompt: true},
		{Role: "user", Text: "  <user_instructions>be brief</user_instructions>", Prompt: true},
		{Role: "user", Text: "<turn_aborted>\nThe user interrupted.", Prompt: true},
	}
	if goal := proxyGoal(messages); goal != "fix the failing test" {
		t.Fatalf("goal = %q", goal)
	}
}

// A model request's parts wait for a call of the proxy's own, so a request
// with more parts than calls in flight gets each of them decided, and hooks
// keep their calls meanwhile.
func TestProxiedPartsWaitForACallAndLeaveHooksTheirs(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	answer := replace("2 tests failed: TestA, TestB")
	c := newTestCompactor(t, func(request Request) (int, any) {
		if request.Delivery == DeliveryProxy {
			<-release
		}
		return answer(request)
	})
	// Before the API's cleanup, which waits for the calls it holds.
	t.Cleanup(free)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const parts = maxProxyLive + 4
	decided := make([]bool, parts)
	var wg sync.WaitGroup
	for i := range parts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := c.proxyOutput("print(run_tests())", bigText(80))
			out.Part = i + 1
			_, decided[i] = c.CompactProxied(ctx, out)
		}()
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if requests, _, _ := c.api.calls(); len(requests) == maxProxyLive {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("proxy calls in flight = %d, want %d", len(requests), maxProxyLive)
		}
	}
	if got := c.Compact(context.Background(), c.bash("make test", bigText(80))); got == nil {
		t.Fatal("a hook found no call free while the proxy's parts waited")
	}
	free()
	wg.Wait()
	for i, ok := range decided {
		if !ok {
			t.Fatalf("part %d was left as it is", i+1)
		}
	}
}
