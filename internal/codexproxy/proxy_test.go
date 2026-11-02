package codexproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/kontext-security/kontext/internal/modelusage"
)

const testToken = "kx0123456789abcdef0123456789abcdef"

// fakeDecider records what it is asked and answers each part with answer.
type fakeDecider struct {
	mu       sync.Mutex
	requests []DecideRequest
	answer   func(Part) *string
	err      error
}

func (d *fakeDecider) Decide(_ context.Context, request DecideRequest) (DecideResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, request)
	if d.err != nil {
		return DecideResponse{}, d.err
	}
	texts := make([]*string, len(request.Parts))
	for i, part := range request.Parts {
		texts[i] = d.answer(part)
	}
	return DecideResponse{Texts: texts}, nil
}

func (d *fakeDecider) asked() []DecideRequest {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]DecideRequest(nil), d.requests...)
}

// headTail keeps a part's first and last three lines.
func headTail(part Part) *string {
	lines := strings.SplitAfter(part.Text, "\n")
	short := strings.Join(lines[:3], "") + "[...]\n" + strings.Join(lines[len(lines)-4:], "")
	return &short
}

func seq(from, to int) string {
	var text strings.Builder
	for i := from; i <= to; i++ {
		fmt.Fprintf(&text, "%d\n", i)
	}
	return text.String()
}

func execResult(output string) string {
	data, _ := json.Marshal(map[string]any{"chunk_id": "a1b2c3", "wall_time_seconds": 0.01, "exit_code": 0, "original_token_count": 900, "output": output})
	return string(data)
}

func message(role, kind, text string) map[string]any {
	return map[string]any{"type": "message", "role": role, "content": []map[string]any{{"type": kind, "text": text}}}
}

func user(text string) map[string]any      { return message("user", "input_text", text) }
func assistant(text string) map[string]any { return message("assistant", "output_text", text) }

func environment(cwd string) map[string]any {
	return user("<environment_context>\n  <cwd>" + cwd + "</cwd>\n  <shell>zsh</shell>\n</environment_context>")
}

func call(callID, script string) map[string]any {
	return map[string]any{"type": "custom_tool_call", "call_id": callID, "name": "exec", "input": script}
}

// result is a code mode call's result: Codex's summary, then what the script
// printed.
func result(callID string, printed ...string) map[string]any {
	parts := []map[string]any{{"type": "input_text", "text": "Script completed\nWall time 0.1 seconds\nOutput:\n"}}
	for _, text := range printed {
		parts = append(parts, map[string]any{"type": "input_text", "text": text})
	}
	return map[string]any{"type": "custom_tool_call_output", "call_id": callID, "output": parts}
}

func body(t *testing.T, input ...any) []byte {
	t.Helper()
	data, err := json.Marshal(map[string]any{"model": "gpt-6.1-sol", "input": input, "stream": true})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// items returns a body's input items as they stand in it.
func items(t *testing.T, b []byte) [][]byte {
	t.Helper()
	request, err := parseRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, len(request.items))
	for i, it := range request.items {
		out[i] = b[it.start:it.end]
	}
	return out
}

// printed returns part of the result of call callID in a body.
func printed(t *testing.T, b []byte, callID string, part int) string {
	t.Helper()
	var request struct {
		Input []struct {
			Type   string          `json:"type"`
			CallID string          `json:"call_id"`
			Output json.RawMessage `json:"output"`
		} `json:"input"`
	}
	if err := json.Unmarshal(b, &request); err != nil {
		t.Fatal(err)
	}
	for _, it := range request.Input {
		if it.Type != "custom_tool_call_output" || it.CallID != callID {
			continue
		}
		var parts []struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal(it.Output, &parts); err != nil || part >= len(parts) {
			t.Fatalf("result of %s is %s", callID, it.Output)
		}
		return parts[part].Text
	}
	t.Fatalf("no result for %s", callID)
	return ""
}

func newRewriter(t *testing.T, decider Decider) *Rewriter {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return NewRewriter(decider, store, time.Second)
}

func TestRewriteShortensNewPartsAndReplaysThem(t *testing.T) {
	decider := &fakeDecider{answer: headTail}
	rw := newRewriter(t, decider)
	id := Identity{SessionID: "019a-session", ThreadID: "019a-thread"}
	script := `text(await tools.exec_command({cmd: "seq 1 3000"}))`
	turn := []any{environment("/work/project"), user("count to 3000"), assistant("Counting."), call("call_1", script), result("call_1", execResult(seq(1, 3000)))}

	first, stats, err := rw.Rewrite(context.Background(), id, body(t, turn...))
	if err != nil || stats.Parts != 1 || stats.Asked != 1 || stats.Replaced != 1 {
		t.Fatalf("first rewrite: %+v, %v", stats, err)
	}
	asked := decider.asked()
	if len(asked) != 1 || len(asked[0].Parts) != 1 {
		t.Fatalf("decisions asked = %+v", asked)
	}
	request := asked[0]
	if request.SessionID != "019a-session" || request.ThreadID != "019a-thread" || request.Model != "gpt-6.1-sol" || request.CWD != "/work/project" ||
		request.Start != 0 || request.Deadline.IsZero() {
		t.Fatalf("request = %+v", request)
	}
	part := request.Parts[0]
	if part.CallID != "call_1" || part.Part != 1 || part.ToolName != "exec" || part.ToolInput != script || part.Text != seq(1, 3000) {
		t.Fatalf("part = %+v", part)
	}
	conversation := request.Conversation()
	if len(conversation.Messages) != 4 || conversation.Messages[0].Text != "count to 3000" || conversation.Messages[2].ToolCall == nil {
		t.Fatalf("conversation = %+v", conversation.Messages)
	}
	var shown struct {
		ExitCode int    `json:"exit_code"`
		Output   string `json:"output"`
	}
	if err := json.Unmarshal([]byte(printed(t, first, "call_1", 1)), &shown); err != nil || shown.Output != *headTail(part) {
		t.Fatalf("shown part = %+v, %v", shown, err)
	}
	if printed(t, first, "call_1", 0) != "Script completed\nWall time 0.1 seconds\nOutput:\n" {
		t.Fatal("Codex's summary part changed")
	}

	// The next request repeats the first in full, original output included.
	turn = append(turn, assistant("Again, shorter."), call("call_2", `text((await tools.exec_command({cmd: "seq 1 2500"})).output)`), result("call_2", seq(1, 2500)))
	second, stats, err := rw.Rewrite(context.Background(), id, body(t, turn...))
	if err != nil || stats.Parts != 2 || stats.Replayed != 1 || stats.Asked != 1 || stats.Replaced != 2 {
		t.Fatalf("second rewrite: %+v, %v", stats, err)
	}
	asked = decider.asked()
	if len(asked) != 2 || len(asked[1].Parts) != 1 || asked[1].Parts[0].CallID != "call_2" {
		t.Fatalf("second request asked about %+v", asked)
	}
	// The context is what the model saw: the first part's cut, not the full
	// output, with the result's parts joined as they are.
	var history string
	for _, message := range asked[1].Messages {
		if message.Role == "tool" && message.ToolUseID == "call_1" {
			history = message.Text
		}
	}
	if want := "Script completed\nWall time 0.1 seconds\nOutput:\n" + printed(t, first, "call_1", 1); history != want {
		t.Fatalf("history shows call_1 as %q", history)
	}
	before, after := items(t, first), items(t, second)
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			t.Fatalf("item %d differs between requests: the cached prefix would break", i)
		}
	}
	if got := printed(t, second, "call_2", 1); got != *headTail(Part{Text: seq(1, 2500)}) {
		t.Fatalf("raw printed part = %q", got)
	}
}

func TestRewriteAsksOnlyAboutNewLargeCodeModeParts(t *testing.T) {
	decider := &fakeDecider{answer: headTail}
	rw := newRewriter(t, decider)
	script := `text(await tools.exec_command({cmd: "seq 1 3000"}))`
	cases := map[string][]any{
		// An output the model has answered was in an earlier request.
		"old":   {user("go"), call("call_1", script), result("call_1", seq(1, 3000)), assistant("Done.")},
		"small": {user("go"), call("call_1", script), result("call_1", seq(1, 10))},
		"function call output": {user("go"), map[string]any{"type": "function_call", "call_id": "call_1", "name": "exec_command", "arguments": "{}"},
			map[string]any{"type": "function_call_output", "call_id": "call_1", "output": seq(1, 3000)}},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			before := len(decider.asked())
			in := body(t, input...)
			out, stats, err := rw.Rewrite(context.Background(), Identity{SessionID: "s-" + strings.ReplaceAll(name, " ", "-")}, in)
			if err != nil || stats.Asked != 0 || !bytes.Equal(out, in) {
				t.Fatalf("rewrite: %+v, %v", stats, err)
			}
			// Nothing to decide, so the daemon is asked nothing.
			if asked := decider.asked(); len(asked) != before {
				t.Fatalf("decision requests = %+v", asked[before:])
			}
		})
	}
}

func TestRewriteDecidesOnceEvenWhenTheDaemonFails(t *testing.T) {
	decider := &fakeDecider{answer: headTail, err: errors.New("daemon unreachable")}
	rw := newRewriter(t, decider)
	in := body(t, user("go"), call("call_1", "text(1)"), result("call_1", seq(1, 3000)))
	out, stats, err := rw.Rewrite(context.Background(), Identity{SessionID: "s1"}, in)
	if err != nil || stats.Asked != 1 || stats.Replaced != 0 || !bytes.Equal(out, in) {
		t.Fatalf("rewrite with the daemon down: %+v, %v", stats, err)
	}
	decider.err = nil
	out, stats, err = rw.Rewrite(context.Background(), Identity{SessionID: "s1"}, in)
	if err != nil || stats.Asked != 0 || stats.Replaced != 0 || !bytes.Equal(out, in) {
		t.Fatalf("the part was decided again: %+v, %v", stats, err)
	}
}

func TestRewriteKeepsEveryOtherByte(t *testing.T) {
	rw := newRewriter(t, &fakeDecider{answer: headTail})
	printedText, _ := json.Marshal(seq(1, 3000))
	in := []byte(`{"input": [ {"type":"message","role":"user","content":[{"type":"input_text","text":"café <b>"}]},` +
		` {"type":"custom_tool_call","call_id":"call_1","name":"exec","input":"text(1)"} ,` +
		"\n\t" + `{"type":"custom_tool_call_output","call_id":"call_1","output":[{"type":"input_text","text":"Script completed\nOutput:\n"},` +
		`{"type":"input_text","text":` + string(printedText) + `}]}],  "model":"gpt-6.1-sol", "extra":{"a":[1,2.50," "]}}`)
	out, stats, err := rw.Rewrite(context.Background(), Identity{SessionID: "s1"}, in)
	if err != nil || stats.Replaced != 1 {
		t.Fatalf("rewrite: %+v, %v", stats, err)
	}
	at := bytes.Index(in, printedText)
	with := encodeString(*headTail(Part{Text: seq(1, 3000)}))
	want := append(append(append([]byte(nil), in[:at]...), with...), in[at+len(printedText):]...)
	if !bytes.Equal(out, want) {
		t.Fatalf("bytes outside the part changed:\n%s", out)
	}
}

func TestStoreKeepsDecisionsAcrossRestarts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "decisions")
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	short := "short"
	store.PutIfAbsent("s1", "k1", &short)
	store.PutIfAbsent("s1", "k2", nil)
	if got := store.PutIfAbsent("s1", "k1", nil); got == nil || *got != "short" {
		t.Fatalf("a second decision replaced the first: %v", got)
	}
	// A session whose decisions no file can hold, for an id that cannot name
	// one or a file that does not open, keeps its parts: a replacement could
	// not be replayed after a restart.
	if err := os.Mkdir(filepath.Join(dir, "s3.jsonl"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, session := range []string{"../s2", "s3"} {
		if got := store.PutIfAbsent(session, "k1", &short); got != nil {
			t.Fatalf("session %s took a replacement no file holds", session)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "s1.jsonl"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("session file = %v, %v", info, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("files = %v", entries)
	}

	store, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got, ok := store.Get("s1", "k1"); !ok || got == nil || *got != "short" {
		t.Fatalf("k1 after a restart = %v, %v", got, ok)
	}
	if got, ok := store.Get("s1", "k2"); !ok || got != nil {
		t.Fatalf("k2 after a restart = %v, %v", got, ok)
	}
}

func TestStorePruneDeletesOldSessions(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	store.PutIfAbsent("old", "k", nil)
	store.PutIfAbsent("new", "k", nil)
	old := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "old.jsonl"), old, old); err != nil {
		t.Fatal(err)
	}
	// Sessions in use are never deleted under the proxy's feet.
	store.now = func() time.Time { return time.Now().Add(2 * storeIdle) }
	if err := store.Prune(7 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "old.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("old session file kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "new.jsonl")); err != nil {
		t.Fatalf("new session file: %v", err)
	}
}

type upstream struct {
	mu      sync.Mutex
	paths   []string
	headers []http.Header
	bodies  [][]byte
}

func (u *upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	if r.Header.Get("Content-Encoding") == "zstd" {
		decoder, _ := zstd.NewReader(nil)
		data, _ = decoder.DecodeAll(data, nil)
		decoder.Close()
	}
	u.mu.Lock()
	u.paths = append(u.paths, r.URL.Path)
	u.headers = append(u.headers, r.Header.Clone())
	u.bodies = append(u.bodies, data)
	u.mu.Unlock()
	w.Header().Set("Content-Type", "text/event-stream")
	_, _ = io.WriteString(w, "data: {}\n\n")
}

// newProxy runs a proxy in front of a recording upstream. logs stops the proxy
// and returns everything it logged.
func newProxy(t *testing.T, rw *Rewriter) (*httptest.Server, *upstream, func() string) {
	t.Helper()
	return newProxyWith(t, Options{Rewriter: rw})
}

// newProxyWith is newProxy with opts, whose upstreams, token and log it
// sets. Both upstreams are the recording one: the Codex backend under
// /backend-api/codex, the OpenAI API under /v1.
func newProxyWith(t *testing.T, opts Options) (*httptest.Server, *upstream, func() string) {
	t.Helper()
	up := &upstream{}
	upServer := httptest.NewServer(up)
	t.Cleanup(upServer.Close)
	opts.Upstream, _ = url.Parse(upServer.URL + "/backend-api/codex")
	opts.APIUpstream, _ = url.Parse(upServer.URL + "/v1")
	opts.Token = testToken
	var mu sync.Mutex
	var logged strings.Builder
	opts.Logf = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		fmt.Fprintf(&logged, format+"\n", args...)
	}
	server, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server)
	t.Cleanup(proxy.Close)
	return proxy, up, func() string {
		proxy.Close()
		mu.Lock()
		defer mu.Unlock()
		return logged.String()
	}
}

func TestProxyForwardsZstdRewritesAndKeepsAuth(t *testing.T) {
	proxy, up, logs := newProxy(t, newRewriter(t, &fakeDecider{answer: headTail}))
	plain := body(t, user("go"), call("call_1", "text(1)"), result("call_1", seq(1, 3000)))
	encoder, _ := zstd.NewWriter(nil)
	compressed := encoder.EncodeAll(plain, nil)
	encoder.Close()
	request, _ := http.NewRequest(http.MethodPost, proxy.URL+"/"+testToken+"/backend-api/codex/responses", bytes.NewReader(compressed))
	request.Header.Set("Authorization", "Bearer secret-access-token")
	request.Header.Set("ChatGPT-Account-Id", "acct-1")
	request.Header.Set("Content-Encoding", "zstd")
	request.Header.Set("X-Codex-Turn-Metadata", `{"session_id":"s1","thread_id":"t1"}`)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	streamed, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(streamed) != "data: {}\n\n" {
		t.Fatalf("response %d %q", response.StatusCode, streamed)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.paths) != 1 || up.paths[0] != "/backend-api/codex/responses" {
		t.Fatalf("upstream paths = %v", up.paths)
	}
	header := up.headers[0]
	if header.Get("Authorization") != "Bearer secret-access-token" || header.Get("ChatGPT-Account-Id") != "acct-1" ||
		header.Get("Content-Encoding") != "zstd" || header.Get("X-Forwarded-For") != "" {
		t.Fatalf("upstream headers = %v", header)
	}
	if got := printed(t, up.bodies[0], "call_1", 1); got != *headTail(Part{Text: seq(1, 3000)}) {
		t.Fatalf("upstream saw %q", got)
	}
	logged := logs()
	if !strings.Contains(logged, "replaced=1") || strings.Contains(logged, testToken) || strings.Contains(logged, "secret-access-token") || strings.Contains(logged, "acct-1") {
		t.Fatalf("logs = %q", logged)
	}
}

func TestProxyRefusesWhatIsNotCodexOnLoopback(t *testing.T) {
	proxy, up, _ := newProxy(t, nil)
	do := func(method, path string, edit func(*http.Request)) (int, string) {
		t.Helper()
		request, _ := http.NewRequest(method, proxy.URL+path, nil)
		if edit != nil {
			edit(request)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(data)
	}
	if code, _ := do(http.MethodGet, "/kxwrong0123456789abcdef0123456789ab/backend-api/codex/models", nil); code != http.StatusNotFound {
		t.Fatalf("wrong token: %d", code)
	}
	if code, _ := do(http.MethodGet, "/"+testToken+"/v1/models", nil); code != http.StatusNotFound {
		t.Fatalf("other route: %d", code)
	}
	if code, _ := do(http.MethodGet, "/"+testToken+"/backend-api/codex/models", func(r *http.Request) { r.Host = "attacker.example:80" }); code != http.StatusForbidden {
		t.Fatalf("rebound host: %d", code)
	}
	websocket := func(r *http.Request) {
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
	}
	if code, _ := do(http.MethodGet, "/"+testToken+"/backend-api/codex/responses", websocket); code != http.StatusUpgradeRequired {
		t.Fatalf("websocket: %d", code)
	}
	if code, text := do(http.MethodGet, "/"+testToken+HealthRoute, nil); code != http.StatusOK || text != HealthBody {
		t.Fatalf("health: %d %q", code, text)
	}
	if code, _ := do(http.MethodPost, "/"+testToken+HealthRoute, nil); code != http.StatusMethodNotAllowed {
		t.Fatalf("health POST: %d", code)
	}
	if code, _ := do(http.MethodGet, "/"+testToken+"/backend-api/codex/models?client_version=0.166.0", nil); code != http.StatusOK {
		t.Fatalf("models: %d", code)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.paths) != 1 || up.paths[0] != "/backend-api/codex/models" {
		t.Fatalf("upstream saw %v", up.paths)
	}
}

func TestProxyPassesUnparsedBodiesThrough(t *testing.T) {
	proxy, up, _ := newProxy(t, newRewriter(t, &fakeDecider{answer: headTail}))
	in := []byte(`{"input": not json`)
	response, err := http.Post(proxy.URL+"/"+testToken+"/backend-api/codex/responses", "application/json", bytes.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.bodies) != 1 || !bytes.Equal(up.bodies[0], in) {
		t.Fatalf("upstream got %q", up.bodies)
	}
}

func TestIdentityPrefersTurnMetadata(t *testing.T) {
	header := http.Header{}
	header.Set("Session-Id", "header-session")
	header.Set("Thread-Id", "header-thread")
	if got := identity(header); got != (Identity{SessionID: "header-session", ThreadID: "header-thread"}) {
		t.Fatalf("headers only: %+v", got)
	}
	header.Set("X-Codex-Turn-Metadata", `{"session_id":"root","thread_id":"subagent","agent_name":"/root/worker"}`)
	if got := identity(header); got != (Identity{SessionID: "root", ThreadID: "subagent"}) {
		t.Fatalf("with turn metadata: %+v", got)
	}
}

func TestServeExitsWhenIdle(t *testing.T) {
	server, err := New(Options{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Serve(context.Background(), listener, server, 50*time.Millisecond) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept running without connections")
	}
}

func TestWireMessagesSendCallInputsAsWritten(t *testing.T) {
	conversation := modelusage.CodexItemsConversation([]json.RawMessage{
		json.RawMessage(`{"type":"function_call","call_id":"call_1","name":"exec_command","arguments":"{\"cmd\": \"ls\"}"}`),
		json.RawMessage(`{"type":"custom_tool_call","call_id":"call_2","name":"exec","input":"text(1)"}`),
	})
	wire := wireMessages(conversation.Messages)
	if len(wire) != 2 || string(wire[0].CallInput) != `"{\"cmd\": \"ls\"}"` || string(wire[1].CallInput) != `"text(1)"` {
		t.Fatalf("call inputs = %s, %s", wire[0].CallInput, wire[1].CallInput)
	}
}

func TestRewriteLeavesPartsPastTheAPIsLimitAlone(t *testing.T) {
	decider := &fakeDecider{answer: headTail}
	rw := newRewriter(t, decider)
	printed := make([]string, maxPart+1)
	for i := range printed {
		printed[i] = "ok\n"
	}
	printed[maxPart] = seq(1, 3000)
	in := body(t, user("go"), call("call_1", "text(1)"), result("call_1", printed...))
	if _, stats, err := rw.Rewrite(context.Background(), Identity{SessionID: "s1"}, in); err != nil || stats.Asked != 0 {
		t.Fatalf("rewrite: %+v, %v", stats, err)
	}
}

func TestProxyLogsWhenCodexHangsUpBeforeTheStreamEnds(t *testing.T) {
	// The backend keeps its stream open past response.completed; Codex reads
	// to there and hangs up.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: response.completed\ndata: {}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL + "/backend-api/codex")
	var mu sync.Mutex
	var logged strings.Builder
	server, err := New(Options{Upstream: upstreamURL, Token: testToken, Rewriter: newRewriter(t, &fakeDecider{answer: headTail}),
		Logf: func(format string, args ...any) { mu.Lock(); fmt.Fprintf(&logged, format+"\n", args...); mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server)
	response, err := http.Post(proxy.URL+"/"+testToken+"/backend-api/codex/responses", "application/json",
		bytes.NewReader(body(t, user("go"))))
	if err != nil {
		t.Fatal(err)
	}
	line, _ := bufio.NewReader(response.Body).ReadString('\n')
	response.Body.Close()
	if line != "event: response.completed\n" {
		t.Fatalf("stream = %q", line)
	}
	proxy.Close()
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(logged.String(), "POST /responses -> 200") {
		t.Fatalf("logs = %q", logged.String())
	}
}

func TestProxyPassesOversizedBodiesThroughWhole(t *testing.T) {
	defer func(limit int64) { bodyLimit = limit }(bodyLimit)
	bodyLimit = 1024
	proxy, up, logs := newProxy(t, newRewriter(t, &fakeDecider{answer: headTail}))
	in := body(t, user(strings.Repeat("x", 4096)))
	response, err := http.Post(proxy.URL+"/"+testToken+"/backend-api/codex/responses", "application/json", bytes.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	up.mu.Lock()
	got := up.bodies
	up.mu.Unlock()
	if len(got) != 1 || !bytes.Equal(got[0], in) {
		t.Fatalf("upstream got %d bytes of %d", len(got[0]), len(in))
	}
	if !strings.Contains(logs(), "too large") {
		t.Fatal("the pass-through was not logged")
	}
}

func TestStoreEndsALineCutShort(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "s1.jsonl"), []byte(`{"k":"a","r":null}`+"\n"+`{"k":"b","r":"sho`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	short := "short"
	store.PutIfAbsent("s1", "c", &short)
	_ = store.Close()
	store, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got, ok := store.Get("s1", "c"); !ok || got == nil || *got != "short" {
		t.Fatalf("the decision after a cut line = %v, %v", got, ok)
	}
	if _, ok := store.Get("s1", "b"); ok {
		t.Fatal("the cut line was read as a decision")
	}
}

// Once no daemon holds the route, requests pass through exactly as Codex sent
// them, asking the daemon nothing; every request asks, so the route goes at
// the first one.
func TestProxyPassesAnUnheldRouteThroughUnasked(t *testing.T) {
	decider := &fakeDecider{answer: headTail}
	var mu sync.Mutex
	asked := 0
	proxy, up, logs := newProxyWith(t, Options{Rewriter: newRewriter(t, decider), Held: func(context.Context) bool {
		mu.Lock()
		defer mu.Unlock()
		asked++
		return false
	}})
	plain := body(t, user("go"), call("call_1", "text(1)"), result("call_1", seq(1, 3000)))
	post, _ := http.NewRequest(http.MethodPost, proxy.URL+"/"+testToken+"/backend-api/codex/responses", bytes.NewReader(plain))
	post.Header.Set("X-Codex-Turn-Metadata", `{"session_id":"s1","thread_id":"t1"}`)
	get, _ := http.NewRequest(http.MethodGet, proxy.URL+"/"+testToken+"/backend-api/codex/models", nil)
	for _, request := range []*http.Request{post, get} {
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.bodies) != 2 || !bytes.Equal(up.bodies[0], plain) {
		t.Fatalf("upstream saw %d requests; the first changed: %v", len(up.bodies), len(up.bodies) > 0 && !bytes.Equal(up.bodies[0], plain))
	}
	mu.Lock()
	defer mu.Unlock()
	if asked != 2 || len(decider.asked()) != 0 {
		t.Fatalf("held asked %d times, the daemon %d", asked, len(decider.asked()))
	}
	if logged := logs(); !strings.Contains(logged, "passed through: no daemon holds the route") {
		t.Fatalf("logs = %q", logged)
	}
}

// Each request goes where the credentials Codex signed it with belong, on
// every route: a ChatGPT login, which names its account, to the Codex
// backend, and an API key, which signs alone, to the OpenAI API. Both get
// their printed parts shortened, their credentials reach the upstream as
// Codex sent them, and neither reaches the log.
func TestProxySendsEachLoginWhereItBelongs(t *testing.T) {
	proxy, up, logs := newProxy(t, newRewriter(t, &fakeDecider{answer: headTail}))
	const apiKey, accessToken = "sk-proj-not-a-real-key", "eyJhbGciOiJub25lIn0.e30.not-a-real-token"
	logins := []struct {
		name, base string
		headers    map[string]string
	}{
		{"ChatGPT", "/backend-api/codex", map[string]string{"Authorization": "Bearer " + accessToken, "ChatGPT-Account-ID": "acct-1"}},
		{"agent identity", "/backend-api/codex", map[string]string{"Authorization": "AgentAssertion not-a-real-assertion", "ChatGPT-Account-ID": "acct-1"}},
		{"API key", "/v1", map[string]string{"Authorization": "Bearer " + apiKey}},
		{"API key naming an account", "/backend-api/codex", map[string]string{"Authorization": "Bearer " + apiKey, "ChatGPT-Account-ID": "acct-1"}},
		{"no credentials", "/backend-api/codex", nil},
	}
	for i, login := range logins {
		callID := fmt.Sprintf("call_%d", i)
		post, _ := http.NewRequest(http.MethodPost, proxy.URL+"/"+testToken+"/backend-api/codex/responses",
			bytes.NewReader(body(t, user("go"), call(callID, "text(1)"), result(callID, seq(1, 3000)))))
		get, _ := http.NewRequest(http.MethodGet, proxy.URL+"/"+testToken+"/backend-api/codex/models?client_version=0.166.0", nil)
		for _, request := range []*http.Request{post, get} {
			for name, value := range login.headers {
				request.Header.Set(name, value)
			}
			request.Header.Set("X-Codex-Turn-Metadata", fmt.Sprintf(`{"session_id":"s%d","thread_id":"t%d"}`, i, i))
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("%s: %s %s -> %d", login.name, request.Method, request.URL.Path, response.StatusCode)
			}
		}
		up.mu.Lock()
		paths, headers, bodies := up.paths[len(up.paths)-2:], up.headers[len(up.headers)-2:], up.bodies[len(up.bodies)-2:]
		up.mu.Unlock()
		if paths[0] != login.base+"/responses" || paths[1] != login.base+"/models" {
			t.Fatalf("%s went to %v, want %s", login.name, paths, login.base)
		}
		for _, header := range headers {
			if header.Get("Authorization") != login.headers["Authorization"] || header.Get("ChatGPT-Account-ID") != login.headers["ChatGPT-Account-ID"] {
				t.Fatalf("%s: the upstream saw other credentials", login.name)
			}
		}
		if got := printed(t, bodies[0], callID, 1); got != *headTail(Part{Text: seq(1, 3000)}) {
			t.Fatalf("%s: the upstream saw %q", login.name, got)
		}
	}
	// Websocket upgrades get 426 whoever signs them.
	upgrade, _ := http.NewRequest(http.MethodGet, proxy.URL+"/"+testToken+"/backend-api/codex/responses", nil)
	upgrade.Header.Set("Authorization", "Bearer "+apiKey)
	upgrade.Header.Set("Connection", "Upgrade")
	upgrade.Header.Set("Upgrade", "websocket")
	response, err := http.DefaultClient.Do(upgrade)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("an API key's websocket upgrade got %d", response.StatusCode)
	}
	if logged := logs(); strings.Contains(logged, apiKey) || strings.Contains(logged, accessToken) || !strings.Contains(logged, "replaced=1") {
		t.Fatalf("logs = %q", logged)
	}
}
