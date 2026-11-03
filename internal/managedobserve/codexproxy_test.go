package managedobserve

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/codexproxy"
	"github.com/kontext-security/kontext/internal/codexroute"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/tooloutput"
)

// compactionAPI answers every compaction with a short text and records the
// requests.
type compactionAPI struct {
	mu       sync.Mutex
	requests []tooloutput.Request
}

func (a *compactionAPI) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if strings.HasSuffix(r.URL.Path, "/tool-output-compaction") {
		var request tooloutput.Request
		_ = json.Unmarshal(body, &request)
		a.mu.Lock()
		a.requests = append(a.requests, request)
		a.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"decision": "replace", "eventId": "evt_proxy_1", "text": "3000 lines; the last is 3000",
			"removedBytes": 10, "removedTokens": 3})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *compactionAPI) calls() []tooloutput.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]tooloutput.Request(nil), a.requests...)
}

func numbered(lines int) string {
	var text strings.Builder
	for i := 1; i <= lines; i++ {
		text.WriteString(strings.Repeat("x", 20) + " line\n")
	}
	return text.String()
}

func TestCodexProxyAnswerDecidesParts(t *testing.T) {
	api := &compactionAPI{}
	server := httptest.NewServer(http.HandlerFunc(api.serve))
	defer server.Close()
	client, err := tooloutput.NewClient(server.URL, "ins_test", func(context.Context) (string, error) { return "install-token", nil }, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "managed-observe", "tool-output")
	compactor := tooloutput.New(tooloutput.Options{Client: client, Enabled: func() bool { return true }, Dir: dir})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); compactor.Run(ctx) }()
	defer func() { cancel(); <-done }()

	printed := numbered(200)
	question, _ := json.Marshal(codexproxy.DecideRequest{
		SessionID: "019a-root", ThreadID: "019a-worker", Model: "gpt-6.1-sol", CWD: "/work",
		Messages: []codexproxy.Message{{Role: "user", Text: "count the lines", Prompt: true}, {Role: "assistant", CallID: "call_1", CallName: "exec", CallInput: json.RawMessage(`"text(1)"`), Response: "1"}},
		Parts:    []codexproxy.Part{{CallID: "call_1", Part: 1, ToolName: "exec", ToolInput: "text(1)", Text: printed}},
	})
	var response codexproxy.DecideResponse
	if err := json.Unmarshal(codexProxyAnswer(compactor)(context.Background(), question), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Texts) != 1 || response.Texts[0] == nil || *response.Texts[0] != "3000 lines; the last is 3000" {
		t.Fatalf("answer = %+v", response)
	}
	requests := api.calls()
	if len(requests) != 1 || requests[0].SessionID != "codex-019a-root" || requests[0].Delivery != tooloutput.DeliveryProxy ||
		requests[0].Part != 1 || requests[0].Context.Goal != "count the lines" {
		t.Fatalf("API requests = %+v", requests)
	}
	if saved, err := os.ReadFile(filepath.Join(dir, "codex-019a-root", "call_1-1.txt")); err != nil || string(saved) != printed {
		t.Fatalf("saved part: %v", err)
	}

	// Shell calls code mode scripts make reach the hooks too, from this
	// session or any other; none of them is sent.
	codeMode := func(session string) hook.Event {
		return hook.Event{SessionID: session, Agent: "codex", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolUseID: "exec-1",
			ToolInput: map[string]any{"command": "seq 1 3000"}, ToolResponse: map[string]any{"content": printed}}
	}
	for _, session := range []string{"codex-019a-root", "codex-019a-worker", "codex-other"} {
		compactor.Observe(context.Background(), codeMode(session))
	}
	if requests = api.calls(); len(requests) != 1 {
		t.Fatalf("after the hooks, API requests = %+v", requests)
	}
}

func TestCodexProxyAnswerWithoutASession(t *testing.T) {
	compactor := tooloutput.New(tooloutput.Options{})
	if answer := codexProxyAnswer(compactor)(context.Background(), json.RawMessage(`{"parts":[]}`)); answer != nil {
		t.Fatalf("answer = %s", answer)
	}
	if answer := codexProxyAnswer(compactor)(context.Background(), json.RawMessage(`not json`)); answer != nil {
		t.Fatalf("answer = %s", answer)
	}
}

func TestCodexProxyAnswerKeepsPartsPastTheProxysDeadline(t *testing.T) {
	api := &compactionAPI{}
	server := httptest.NewServer(http.HandlerFunc(api.serve))
	defer server.Close()
	client, err := tooloutput.NewClient(server.URL, "ins_test", func(context.Context) (string, error) { return "install-token", nil }, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	compactor := tooloutput.New(tooloutput.Options{Client: client, Enabled: func() bool { return true }, Dir: filepath.Join(t.TempDir(), "tool-output")})
	question, _ := json.Marshal(codexproxy.DecideRequest{SessionID: "019a", Deadline: time.Now().Add(50 * time.Millisecond),
		Parts: []codexproxy.Part{{CallID: "call_1", Part: 1, ToolName: "exec", ToolInput: "text(1)", Text: numbered(200)}}})
	var response codexproxy.DecideResponse
	if err := json.Unmarshal(codexProxyAnswer(compactor)(context.Background(), question), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Texts) != 1 || response.Texts[0] != nil || len(api.calls()) != 0 {
		t.Fatalf("answer = %+v after %d API calls", response, len(api.calls()))
	}
}

// Where Codex's route stands reaches the daemon's log with debug output off,
// since routing edits ~/.codex/config.toml: once when the switch first
// arrives, and again only when that changes.
func TestCodexRoutingLogsWhereTheRouteStands(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("the router locks the route and copies the binary on macOS and Linux only")
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".codex", "config.toml"), []byte("model = \"gpt-6.1-sol\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "kontext"), []byte("kontext\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	binary, err := os.Open(filepath.Join(home, "kontext"))
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()
	var mu sync.Mutex
	loaded := false
	launchctl := func(_ context.Context, args ...string) error {
		mu.Lock()
		defer mu.Unlock()
		switch args[0] {
		case "print":
			if !loaded {
				return errors.New("could not find service")
			}
		case "bootstrap":
			loaded = true
		case "bootout":
			loaded = false
		}
		return nil
	}
	router := codexroute.New(codexroute.Options{Home: home, Binary: binary, StateDir: filepath.Join(home, "state"),
		Socket: filepath.Join(home, "kontext.sock"), GOOS: "darwin", Launchctl: launchctl,
		Health:     func(context.Context, int, string) error { return nil },
		Reach:      func(context.Context, int, string) error { return nil },
		CodexSince: func(time.Time) (int, error) { return 0, nil },
		FreePort:   func() (int, error) { return 49321, nil }})

	stderr, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = stderr
	defer func() { os.Stderr = previous; stderr.Close() }()
	c := &codexRouting{router: router, diagnostic: diagnostic.New(io.Discard, false), switched: make(chan bool, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	logged := func(want string) string {
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			data, _ := os.ReadFile(stderr.Name())
			if strings.Contains(string(data), want) || time.Now().After(deadline) {
				return string(data)
			}
		}
	}

	c.switched <- true
	c.switched <- true
	c.switched <- false
	log := logged("codex proxy: not routed: switch off\n")
	if log != "codex proxy: routed through 127.0.0.1:49321\ncodex proxy: not routed: switch off\n" {
		t.Fatalf("log:\n%s", log)
	}
}
