package codexproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/kontext-security/kontext/internal/localruntime"
)

// e2eScripts are the code mode scripts the mock model runs, in turn: a
// printed exec_command result, and a command's output printed raw.
var e2eScripts = []string{
	`text(await tools.exec_command({cmd:"seq 1 3000"}));`,
	`const r = await tools.exec_command({cmd:"seq 1 2500"}); text(r.output);`,
}

// e2eModel is a made-up catalog entry for a model that, like Codex's current
// ones, only gets code mode. Codex keeps code mode to the models it ships
// with, so the entry takes the slug of one.
const e2eModel = `{"slug":"gpt-6.1-sol","display_name":"Kontext e2e","description":"A code mode only test model",
"default_reasoning_level":"low","supported_reasoning_levels":[{"effort":"low","description":"low"}],"shell_type":"unified_exec",
"visibility":"list","supported_in_api":true,"priority":1,"support_verbosity":true,"default_verbosity":"low",
"apply_patch_tool_type":"freeform","truncation_policy":{"mode":"tokens","limit":10000},"context_window":200000,
"experimental_supported_tools":[],"input_modalities":["text"],"use_responses_lite":true,"tool_mode":"code_mode_only"}`

// e2eBackend stands in for chatgpt.com and api.openai.com: the Codex
// backend's models and responses, the account check Codex makes before its
// first turn, and the OpenAI API's responses. Each user turn gets one call
// per script, then DONE.
type e2eBackend struct {
	mu        sync.Mutex
	responses [][]byte
	// paths and signed hold each model request's path and Authorization, and
	// catalogs each models request's path.
	paths     []string
	signed    []string
	catalogs  []string
	websocket int
	other     []string
}

func (b *e2eBackend) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	if strings.EqualFold(r.Header.Get("Content-Encoding"), "zstd") {
		decoder, _ := zstd.NewReader(nil)
		raw, _ = decoder.DecodeAll(raw, nil)
		decoder.Close()
	}
	path := strings.TrimRight(r.URL.Path, "/")
	switch {
	case strings.EqualFold(r.Header.Get("Upgrade"), "websocket"):
		b.mu.Lock()
		b.websocket++
		b.mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/accounts/check"):
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"accounts":[{"id":"acct-e2e","plan_type":"plus","workspace_backend_origin":"https://chatgpt.com/",`+
			`"account_routing_override":"NO_CONSTRAINT"}],"account_ordering":["acct-e2e"],"default_account_id":"acct-e2e"}`)
	case r.Method == http.MethodGet && strings.HasSuffix(path, "/models"):
		b.mu.Lock()
		b.catalogs = append(b.catalogs, path)
		b.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"models":[`+e2eModel+`]}`)
	case r.Method == http.MethodPost && (strings.HasSuffix(path, "/codex/responses") || strings.HasSuffix(path, "/v1/responses")):
		var request struct {
			Input []json.RawMessage `json:"input"`
		}
		if json.Unmarshal(raw, &request) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		b.mu.Lock()
		b.responses = append(b.responses, raw)
		b.paths, b.signed = append(b.paths, path), append(b.signed, r.Header.Get("Authorization"))
		n := len(b.responses)
		b.mu.Unlock()
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write(e2eStream(e2eAnswer(request.Input, n), n))
	default:
		b.mu.Lock()
		b.other = append(b.other, r.Method+" "+path)
		b.mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}
}

func e2eAnswer(input []json.RawMessage, n int) []map[string]any {
	results := 0
	for _, raw := range input {
		var head struct{ Type, Role string }
		_ = json.Unmarshal(raw, &head)
		switch {
		case head.Type == "message" && head.Role == "user":
			results = 0
		case head.Type == "custom_tool_call_output":
			results++
		}
	}
	if results < len(e2eScripts) {
		return []map[string]any{{"type": "custom_tool_call", "id": fmt.Sprintf("ctc_%d", n), "call_id": fmt.Sprintf("call_%d", n),
			"name": "exec", "status": "completed", "input": e2eScripts[results]}}
	}
	return []map[string]any{{"id": fmt.Sprintf("msg_%d", n), "type": "message", "role": "assistant", "status": "completed",
		"content": []map[string]any{{"type": "output_text", "text": "DONE", "annotations": []any{}}}}}
}

// e2eStream is the server-sent event stream of a response with items.
func e2eStream(items []map[string]any, n int) []byte {
	response := map[string]any{"id": fmt.Sprintf("resp_%d", n), "object": "response", "created_at": 0, "status": "completed",
		"model": "gpt-6.1-sol", "output": items, "usage": map[string]any{"input_tokens": 10, "output_tokens": 2, "total_tokens": 12}}
	started := map[string]any{}
	for k, v := range response {
		started[k] = v
	}
	started["status"], started["output"] = "in_progress", []any{}
	events := []map[string]any{{"type": "response.created", "response": started}}
	for i, item := range items {
		added := map[string]any{}
		for k, v := range item {
			added[k] = v
		}
		added["status"] = "in_progress"
		events = append(events, map[string]any{"type": "response.output_item.added", "output_index": i, "item": added})
		if item["type"] == "custom_tool_call" {
			events = append(events,
				map[string]any{"type": "response.custom_tool_call_input.delta", "item_id": item["id"], "output_index": i, "delta": item["input"]},
				map[string]any{"type": "response.custom_tool_call_input.done", "item_id": item["id"], "output_index": i, "input": item["input"]})
		} else {
			text := item["content"].([]map[string]any)[0]["text"]
			events = append(events, map[string]any{"type": "response.output_text.delta", "item_id": item["id"], "output_index": i, "content_index": 0, "delta": text})
		}
		events = append(events, map[string]any{"type": "response.output_item.done", "output_index": i, "item": item})
	}
	events = append(events, map[string]any{"type": "response.completed", "response": response})
	var stream bytes.Buffer
	for _, event := range events {
		data, _ := json.Marshal(event)
		fmt.Fprintf(&stream, "event: %s\ndata: %s\n\n", event["type"], data)
	}
	return stream.Bytes()
}

// e2eLogin is a ChatGPT login Codex accepts offline: unsigned tokens, fresh,
// with nothing behind them.
func e2eLogin() string {
	segment := func(value any) string {
		data, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	auth := map[string]string{"chatgpt_plan_type": "plus", "chatgpt_user_id": "user-e2e", "chatgpt_account_id": "acct-e2e"}
	expires := time.Now().Add(30 * 24 * time.Hour).Unix()
	token := func(claims map[string]any) string {
		return segment(map[string]string{"alg": "none", "typ": "JWT"}) + "." + segment(claims) + ".e2e"
	}
	login, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "OPENAI_API_KEY": nil,
		"tokens": map[string]string{
			"id_token":      token(map[string]any{"exp": expires, "email": "e2e@example.invalid", "https://api.openai.com/auth": auth}),
			"access_token":  token(map[string]any{"exp": expires, "https://api.openai.com/auth": auth}),
			"refresh_token": "e2e-refresh", "account_id": "acct-e2e"},
		"last_refresh": time.Now().UTC().Format(time.RFC3339)})
	return string(login)
}

// TestCodexEndToEnd runs a real Codex binary through the proxy against a mock
// backend and a fake daemon, signed in with ChatGPT and with an API key: no
// real credentials, no model calls, and a Seatbelt profile that refuses every
// connection off the machine. Opt in with KONTEXT_CODEX_E2E_BIN=/path/to/codex
// (see scripts/codex-proxy-e2e.sh).
func TestCodexEndToEnd(t *testing.T) {
	codex := os.Getenv("KONTEXT_CODEX_E2E_BIN")
	if codex == "" {
		t.Skip("set KONTEXT_CODEX_E2E_BIN to a Codex binary to run")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("uses sandbox-exec; macOS only")
	}
	for _, login := range []struct{ name, auth, base string }{
		// A ChatGPT login's requests go to the Codex backend, and an API
		// key's to the OpenAI API.
		{"ChatGPT", e2eLogin(), "/backend-api/codex"},
		{"API key", `{"auth_mode":"apikey","OPENAI_API_KEY":"` + e2eAPIKey + `"}`, "/v1"},
	} {
		t.Run(login.name, func(t *testing.T) { codexEndToEnd(t, codex, login.auth, login.base) })
	}
}

// e2eAPIKey has an API key's shape and nothing behind it.
const e2eAPIKey = "sk-e2e-0000000000000000000000000000000000000000"

// codexEndToEnd runs two turns of Codex, signed in with auth, whose model
// requests must reach the backend under base.
func codexEndToEnd(t *testing.T, codex, auth, base string) {
	backend := &e2eBackend{}
	// Two origins, as in production: model traffic, and the ChatGPT backend
	// Codex reaches directly.
	models, chatgpt := httptest.NewServer(backend), httptest.NewServer(backend)
	defer models.Close()
	defer chatgpt.Close()

	var mu sync.Mutex
	var questions []DecideRequest
	socket := fakeDaemon(t, func(question DecideRequest) DecideResponse {
		mu.Lock()
		questions = append(questions, question)
		mu.Unlock()
		texts := make([]*string, len(question.Parts))
		for i, part := range question.Parts {
			texts[i] = headTail(part)
		}
		return DecideResponse{Texts: texts}
	})
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	upstream, _ := url.Parse(models.URL + "/backend-api/codex")
	apiUpstream, _ := url.Parse(models.URL + "/v1")
	var logged strings.Builder
	var logMu sync.Mutex
	server, err := New(Options{Upstream: upstream, APIUpstream: apiUpstream, Token: testToken, Rewriter: NewRewriter(SocketDecider{Client: localruntime.NewClient(socket)}, store, DecideWait),
		Logf: func(format string, args ...any) {
			logMu.Lock()
			fmt.Fprintf(&logged, format+"\n", args...)
			logMu.Unlock()
		}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := Listen(0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- Serve(ctx, listener, server, 0) }()
	defer func() { cancel(); <-served }()

	root, err := os.MkdirTemp("/tmp", "kx-codex-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	home, workspace := filepath.Join(root, "home"), filepath.Join(root, "workspace")
	codexHome := filepath.Join(home, ".codex")
	for _, dir := range []string{codexHome, workspace} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(codexHome, "auth.json"), []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}
	baseURL := BaseURL(listener.Addr(), testToken)
	config := fmt.Sprintf("model = \"gpt-6.1-sol\"\ncli_auth_credentials_store = \"file\"\nweb_search = \"disabled\"\nopenai_base_url = %q\nchatgpt_base_url = %q\n",
		baseURL, chatgpt.URL+"/backend-api/")
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(root, "sandbox.sb")
	sandbox := "(version 1)\n(allow default)\n(deny network-outbound)\n(allow network-outbound (remote ip \"localhost:*\"))\n(allow network-outbound (remote unix-socket))\n"
	if err := os.WriteFile(profile, []byte(sandbox), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(prompt string, resume bool) string {
		t.Helper()
		args := []string{"-f", profile, codex, "-c", "features.code_mode_host=true", "exec"}
		if resume {
			args = append(args, "resume", "--last")
		}
		args = append(args, "--skip-git-repo-check", "--json", "--dangerously-bypass-approvals-and-sandbox", "-")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sandbox-exec", args...)
		cmd.Dir, cmd.Stdin = workspace, strings.NewReader(prompt)
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + home, "CODEX_HOME=" + codexHome, "CI=1", "NO_COLOR=1", "LANG=en_US.UTF-8"}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("codex exec: %v\nstderr:\n%s", err, stderr.String())
		}
		return stdout.String()
	}
	first := run("Run the scripts, then reply DONE.", false)
	second := run("Run them again, then reply DONE.", true)

	for name, events := range map[string]string{"first turn": first, "second turn": second} {
		if !strings.Contains(events, `"text":"DONE"`) {
			t.Fatalf("%s did not finish:\n%s", name, events)
		}
		// The 426 makes Codex use HTTP at once, without retries or warnings.
		if strings.Contains(events, "Reconnecting") || strings.Contains(events, "Falling back") {
			t.Fatalf("%s showed transport errors:\n%s", name, events)
		}
	}
	backend.mu.Lock()
	responses, websocket := append([][]byte(nil), backend.responses...), backend.websocket
	paths, signed := append([]string(nil), backend.paths...), append([]string(nil), backend.signed...)
	t.Logf("model catalog requests: %v", backend.catalogs)
	backend.mu.Unlock()
	if websocket != 0 {
		t.Fatalf("the backend saw %d websocket upgrades; the proxy should answer them", websocket)
	}
	if len(responses) != 6 {
		t.Fatalf("the backend saw %d model requests, want 6", len(responses))
	}
	for i, path := range paths {
		if path != base+"/responses" || (base == "/v1") != (signed[i] == "Bearer "+e2eAPIKey) {
			t.Fatalf("model request %d went to %s, signed %.12s…; want %s/responses", i+1, path, signed[i], base)
		}
	}
	// What the model read of each printed part is the shortened text, and
	// every request starts with the one before it, byte for byte.
	for i := 1; i < len(responses); i++ {
		before, after := items(t, responses[i-1]), items(t, responses[i])
		if len(after) < len(before) {
			t.Fatalf("request %d has fewer items than request %d", i+1, i)
		}
		for j := range before {
			if !bytes.Equal(before[j], after[j]) {
				t.Fatalf("item %d of request %d differs in request %d: the cached prefix breaks", j, i, i+1)
			}
		}
	}
	last := responses[len(responses)-1]
	var shown struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal([]byte(printed(t, last, "call_1", 1)), &shown); err != nil || shown.Output != *headTail(Part{Text: seq(1, 3000)}) {
		t.Fatalf("the model read %q of the printed exec_command result (%v)", shown.Output, err)
	}
	if got := printed(t, last, "call_2", 1); got != *headTail(Part{Text: seq(1, 2500)}) {
		t.Fatalf("the model read %q of the raw printed output", got)
	}
	mu.Lock()
	asked, sessions := 0, map[string]bool{}
	for _, question := range questions {
		asked += len(question.Parts)
		sessions[question.SessionID] = true
	}
	mu.Unlock()
	if asked != 4 || len(sessions) != 1 || sessions[""] {
		t.Fatalf("the daemon was asked about %d parts in sessions %v, want 4 in one", asked, sessions)
	}
	// The token lives in config.toml and nowhere else Codex writes.
	err = filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || path == filepath.Join(codexHome, "config.toml") {
			return err
		}
		if data, err := os.ReadFile(path); err == nil && bytes.Contains(data, []byte(testToken)) {
			return fmt.Errorf("the token is in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if strings.Contains(logged.String(), testToken) || strings.Contains(logged.String(), e2eAPIKey) {
		t.Fatal("the proxy logged its token or the API key")
	}
}
