package tooloutput

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/privacyfolder"
)

const (
	testSession   = "1f0c5e2a-0d7a-4a43-9b51-6f2a8f1c9d10"
	testToolUseID = "toolu_01AbCdEf"
	testEventID   = "evt_0001"
)

// fakeAPI is the Kontext API's compaction endpoints. reply answers each
// compaction request; read-backs are recorded.
type fakeAPI struct {
	t      *testing.T
	server *httptest.Server
	reply  func(Request) (int, any)

	mu        sync.Mutex
	requests  []Request
	readBacks []ReadBack
	paths     []string
}

func newFakeAPI(t *testing.T, reply func(Request) (int, any)) *fakeAPI {
	t.Helper()
	api := &fakeAPI{t: t, reply: reply}
	api.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer install-token" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("request %s %s, headers %v", r.Method, r.URL.Path, r.Header)
		}
		body, _ := io.ReadAll(r.Body)
		api.mu.Lock()
		api.paths = append(api.paths, r.URL.Path)
		api.mu.Unlock()
		switch r.URL.Path {
		case "/api/v1/installations/ins_test/tool-output-compaction":
			var request Request
			if err := json.Unmarshal(body, &request); err != nil {
				t.Errorf("decode request: %v", err)
			}
			api.mu.Lock()
			api.requests = append(api.requests, request)
			api.mu.Unlock()
			status, answer := api.reply(request)
			w.WriteHeader(status)
			if text, isText := answer.(string); isText {
				_, _ = w.Write([]byte(text))
			} else {
				_ = json.NewEncoder(w).Encode(answer)
			}
		case "/api/v1/installations/ins_test/tool-output-compaction/read-backs":
			var readBack ReadBack
			if err := json.Unmarshal(body, &readBack); err != nil {
				t.Errorf("decode read-back: %v", err)
			}
			api.mu.Lock()
			api.readBacks = append(api.readBacks, readBack)
			api.mu.Unlock()
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(api.server.Close)
	return api
}

func (a *fakeAPI) calls() ([]Request, []ReadBack, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Request(nil), a.requests...), append([]ReadBack(nil), a.readBacks...), len(a.paths)
}

func replace(text string) func(Request) (int, any) {
	return func(Request) (int, any) {
		return http.StatusOK, map[string]any{"decision": "replace", "eventId": testEventID, "text": text, "removedBytes": 10, "removedTokens": 3}
	}
}

type testCompactor struct {
	*Compactor
	api  *fakeAPI
	on   *atomic.Bool
	home string
	cwd  string
}

func newTestCompactor(t *testing.T, reply func(Request) (int, any)) testCompactor {
	t.Helper()
	api := newFakeAPI(t, reply)
	client, err := NewClient(api.server.URL, "ins_test", func(context.Context) (string, error) { return "install-token", nil }, api.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	on := &atomic.Bool{}
	on.Store(true)
	root := t.TempDir()
	home := filepath.Join(root, "home")
	cwd := filepath.Join(root, "project")
	for _, dir := range []string{home, cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	compactor := New(Options{
		Client:  client,
		Enabled: on.Load,
		Dir:     filepath.Join(root, "data", "managed-observe", "tool-output"),
		Home:    home,
	})
	return testCompactor{Compactor: compactor, api: api, on: on, home: home, cwd: cwd}
}

func bigText(lines int) string {
	var text strings.Builder
	for i := 1; i <= lines; i++ {
		text.WriteString("line ")
		text.WriteString(strings.Repeat("x", 40))
		text.WriteString(" ")
		text.WriteString(string(rune('a' + i%26)))
		text.WriteString("\n")
	}
	return text.String()
}

func (c testCompactor) bash(command, stdout string) hook.Event {
	return hook.Event{
		SessionID: testSession,
		Agent:     "claude",
		HookName:  hook.HookPostToolUse,
		ToolName:  "Bash",
		ToolUseID: testToolUseID,
		CWD:       c.cwd,
		ToolInput: map[string]any{"command": command, "description": "Run the tests"},
		ToolResponse: map[string]any{
			"stdout": stdout, "stderr": "warning: slow", "interrupted": false, "isImage": false, "noOutputExpected": false,
		},
	}
}

func (c testCompactor) read(path, content string, start int) hook.Event {
	return hook.Event{
		SessionID: testSession,
		Agent:     "claude",
		HookName:  hook.HookPostToolUse,
		ToolName:  "Read",
		ToolUseID: testToolUseID,
		CWD:       c.cwd,
		ToolInput: map[string]any{"file_path": path},
		ToolResponse: map[string]any{
			"type": "text",
			"file": map[string]any{"filePath": path, "content": content, "numLines": json.Number("60"), "startLine": json.Number(strconv.Itoa(start)), "totalLines": json.Number("60")},
		},
	}
}

func TestSwitchOffSendsNothing(t *testing.T) {
	c := newTestCompactor(t, replace("short"))
	c.on.Store(false)
	if got := c.Compact(context.Background(), c.bash("make test", bigText(80))); got != nil {
		t.Fatalf("Compact() = %v with the switch off", got)
	}
	c.Observe(context.Background(), hook.Event{SessionID: "codex-1", Agent: "codex", HookName: hook.HookPostToolUse, ToolName: "Bash",
		CWD: c.cwd, ToolInput: map[string]any{"command": "cat log"}, ToolResponse: map[string]any{"content": bigText(80)}})
	if _, _, calls := c.api.calls(); calls != 0 {
		t.Fatalf("API calls with the switch off = %d", calls)
	}
	if len(c.shadow) != 0 {
		t.Fatal("a shadow request was queued with the switch off")
	}
}

func TestLiveBashReplacesStdoutAndSavesTheFullOutput(t *testing.T) {
	c := newTestCompactor(t, replace("kept head\n[omitted]\nkept tail\n"))
	stdout := bigText(80)
	event := c.bash("make test", stdout)
	got := c.Compact(context.Background(), event)
	if got == nil {
		t.Fatal("Compact() = nil, want a replacement")
	}
	want := map[string]any{"stdout": "kept head\n[omitted]\nkept tail\n", "stderr": "warning: slow", "interrupted": false, "isImage": false, "noOutputExpected": false}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rebuilt tool response = %#v, want %#v", got, want)
	}
	if event.ToolResponse["stdout"] != stdout {
		t.Fatal("the event's own tool response was changed")
	}

	requests, _, _ := c.api.calls()
	if len(requests) != 1 {
		t.Fatalf("requests = %d", len(requests))
	}
	request := requests[0]
	saved := filepath.Join(c.dir, testSession, testToolUseID+".txt")
	if request.Mode != ModeLive || request.Agent != "claude-code" || request.SessionID != testSession || request.ToolUseID != testToolUseID ||
		request.ToolName != "Bash" || request.Output.Kind != KindText || request.Output.Text != stdout || request.Output.RecoveryPath != saved {
		t.Fatalf("request = %+v", request)
	}
	if request.ToolInput["command"] != "make test" || request.Context.Current.ToolName != "Bash" || request.Context.Current.ToolInput["command"] != "make test" {
		t.Fatalf("request tool input = %+v, current = %+v", request.ToolInput, request.Context.Current)
	}

	data, err := os.ReadFile(saved)
	if err != nil || string(data) != stdout {
		t.Fatalf("saved output = %q, %v", data, err)
	}
	if runtime.GOOS != "windows" {
		for path, mode := range map[string]os.FileMode{saved: 0o600, filepath.Dir(saved): 0o700, c.dir: 0o700} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != mode {
				t.Errorf("%s mode = %v, %v, want %o", path, info.Mode().Perm(), err, mode)
			}
		}
	}
}

func TestLiveReadReplacesContentAndKeepsTheFile(t *testing.T) {
	content := bigText(60)
	lines := strings.Split(content, "\n")
	// Lines 21-40 of a Read starting at line 1 become one marker and padding.
	replaced := strings.Join(lines[:20], "\n") + "\n[omitted lines 21-40]" + strings.Repeat("\n", 20) + strings.Join(lines[40:], "\n")
	c := newTestCompactor(t, replace(replaced))
	path := filepath.Join(c.cwd, "main.go")
	got := c.Compact(context.Background(), c.read(path, content, 1))
	if got == nil {
		t.Fatal("Compact() = nil, want a replacement")
	}
	file := got["file"].(map[string]any)
	if got["type"] != "text" || file["content"] != replaced || file["filePath"] != path || file["numLines"] != json.Number("60") {
		t.Fatalf("rebuilt tool response = %#v", got)
	}
	requests, _, _ := c.api.calls()
	if output := requests[0].Output; output.Kind != KindFileLines || output.FilePath != path || output.StartLine != 1 || output.RecoveryPath != "" {
		t.Fatalf("request output = %+v", output)
	}
	if entries, _ := os.ReadDir(filepath.Join(c.dir, testSession)); len(entries) != 1 || entries[0].Name() != testToolUseID+".json" {
		t.Fatalf("a Read saves only its record, got %v", entries)
	}
	if records := c.sessions[testSession].records; len(records) != 1 || !reflect.DeepEqual(records[0].Omitted, [][2]int{{21, 40}}) {
		t.Fatalf("records = %+v", records)
	}
}

func TestPersistedBashOutputIsLeftToClaudeCode(t *testing.T) {
	c := newTestCompactor(t, replace("short"))
	event := c.bash("cat big.log", bigText(80))
	event.ToolResponse["persistedOutputPath"] = "/Users/x/.claude/projects/p/tool-results/b1.txt"
	if got := c.Compact(context.Background(), event); got != nil {
		t.Fatalf("Compact() = %v for a persisted output", got)
	}
	small := c.bash("ls", strings.Repeat("a", minOutputBytes))
	if got := c.Compact(context.Background(), small); got != nil {
		t.Fatal("an output of 2048 bytes was sent")
	}
	if _, _, calls := c.api.calls(); calls != 0 {
		t.Fatalf("API calls = %d", calls)
	}
}

// Calls in the folders macOS guards (Desktop, Documents, Downloads, iCloud
// Drive...) are compacted like any other: the output comes with the event.
func TestCompactsInPrivacyFolders(t *testing.T) {
	enabled := privacyfolder.Enabled
	privacyfolder.Enabled = true
	t.Cleanup(func() { privacyfolder.Enabled = enabled })
	c := newTestCompactor(t, replace("short"))
	project := filepath.Join(c.home, "Desktop", "projects", "app")

	bash := c.bash("make test", bigText(80))
	bash.CWD = project
	read := c.read(filepath.Join(c.home, "Documents", "plan.md"), bigText(60), 1)
	read.ToolUseID = "toolu_read"
	read.CWD = project
	if c.Compact(context.Background(), bash) == nil {
		t.Fatal("a Bash output from a Desktop project was not compacted")
	}
	if c.Compact(context.Background(), read) != nil {
		t.Fatal("the Read's fake reply keeps one line, so it must be refused, not skipped")
	}
	codex := hook.Event{SessionID: "codex-1", Agent: "codex", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolUseID: "call_1", CWD: project,
		ToolInput: map[string]any{"command": "cat ~/Downloads/report.csv"}, ToolResponse: map[string]any{"content": bigText(80)}}
	c.Observe(context.Background(), codex)
	c.sendShadow(context.Background(), <-c.shadow)
	requests, _, _ := c.api.calls()
	if len(requests) != 3 || requests[0].ToolName != "Bash" || requests[1].Output.FilePath != read.ToolResponse["file"].(map[string]any)["filePath"] || requests[2].Mode != ModeShadow {
		t.Fatalf("requests = %+v", requests)
	}
}

func TestFailuresLeaveTheOutputUnchanged(t *testing.T) {
	previous := apiWait
	apiWait = 100 * time.Millisecond
	t.Cleanup(func() { apiWait = previous })
	stdout := bigText(80)
	for name, reply := range map[string]func(Request) (int, any){
		"timeout": func(Request) (int, any) {
			time.Sleep(3 * apiWait)
			return http.StatusOK, map[string]any{"decision": "replace", "eventId": testEventID, "text": "late"}
		},
		"server error": func(Request) (int, any) {
			return http.StatusInternalServerError, map[string]any{"decision": "replace", "eventId": testEventID, "text": "x"}
		},
		"not found": func(Request) (int, any) { return http.StatusNotFound, "" },
		"not json":  func(Request) (int, any) { return http.StatusOK, "<html>" },
		"unknown decision": func(Request) (int, any) {
			return http.StatusOK, map[string]any{"decision": "trim", "eventId": testEventID, "text": "x"}
		},
		"replace without text": func(Request) (int, any) {
			return http.StatusOK, map[string]any{"decision": "replace", "eventId": testEventID}
		},
		"missing event": func(Request) (int, any) { return http.StatusOK, map[string]any{"decision": "replace", "text": "x"} },
		"not shorter":   replace(stdout + "more"),
		"keep": func(Request) (int, any) {
			return http.StatusOK, map[string]any{"decision": "keep", "eventId": testEventID}
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestCompactor(t, reply)
			started := time.Now()
			if got := c.Compact(context.Background(), c.bash("make test", stdout)); got != nil {
				t.Fatalf("Compact() = %v", got)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("Compact() took %v", elapsed)
			}
			if _, err := os.Stat(filepath.Join(c.dir, testSession, testToolUseID+".txt")); !os.IsNotExist(err) {
				t.Fatalf("an output was saved: %v", err)
			}
		})
	}

	t.Run("read line count changed", func(t *testing.T) {
		c := newTestCompactor(t, replace("only one line"))
		if got := c.Compact(context.Background(), c.read(filepath.Join(c.cwd, "main.go"), bigText(60), 1)); got != nil {
			t.Fatalf("Compact() = %v", got)
		}
	})
	t.Run("unsaved output", func(t *testing.T) {
		c := newTestCompactor(t, replace("short"))
		// A file where the save directory should be: nothing can be saved.
		if err := os.MkdirAll(filepath.Dir(c.dir), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(c.dir, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := c.Compact(context.Background(), c.bash("make test", stdout)); got != nil {
			t.Fatalf("Compact() = %v without a saved output", got)
		}
	})
}

func TestReadingASavedOutputBackIsNeverCompacted(t *testing.T) {
	c := newTestCompactor(t, replace("short"))
	saved := filepath.Join(c.dir, "other-session", "toolu_x.txt")
	for _, command := range []string{
		"cat " + saved,
		"sed -n 1,200p " + strings.ReplaceAll(saved, " ", `\ `),
		"ls " + filepath.Dir(c.dir) + "/tool-output/",
	} {
		if got := c.Compact(context.Background(), c.bash(command, bigText(80))); got != nil {
			t.Errorf("Compact(%q) = %v", command, got)
		}
	}
	if got := c.Compact(context.Background(), c.read(saved, bigText(60), 1)); got != nil {
		t.Errorf("a Read of a saved output was compacted")
	}
	if _, _, calls := c.api.calls(); calls != 0 {
		t.Fatalf("API calls = %d", calls)
	}
}

func TestReadBacksAreReportedOncePerCall(t *testing.T) {
	content := bigText(60)
	lines := strings.Split(content, "\n")
	replaced := strings.Join(lines[:20], "\n") + "\n[omitted]" + strings.Repeat("\n", 20) + strings.Join(lines[40:], "\n")
	c := newTestCompactor(t, func(request Request) (int, any) {
		if request.Output.Kind == KindFileLines {
			return http.StatusOK, map[string]any{"decision": "replace", "eventId": "evt_read", "text": replaced}
		}
		return http.StatusOK, map[string]any{"decision": "replace", "eventId": "evt_bash", "text": "short"}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	if c.Compact(context.Background(), c.bash("make test", bigText(80))) == nil {
		t.Fatal("bash not compacted")
	}
	path := filepath.Join(c.cwd, "main.go")
	readEvent := c.read(path, content, 1)
	readEvent.ToolUseID = "toolu_read"
	if c.Compact(context.Background(), readEvent) == nil {
		t.Fatal("read not compacted")
	}

	saved := filepath.Join(c.dir, testSession, testToolUseID+".txt")
	catBack := hook.Event{SessionID: testSession, Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolUseID: "toolu_cat",
		CWD: c.cwd, ToolInput: map[string]any{"command": "sed -n 100,200p '" + saved + "'"}}
	c.Observe(context.Background(), catBack)
	catBack.HookName = hook.HookPostToolUse
	c.Observe(context.Background(), catBack)
	readBack := hook.Event{SessionID: testSession, Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Read", ToolUseID: "toolu_reread",
		CWD: c.cwd, ToolInput: map[string]any{"file_path": path, "offset": json.Number("25"), "limit": json.Number("10")}}
	c.Observe(context.Background(), readBack)
	elsewhere := hook.Event{SessionID: testSession, Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Read", ToolUseID: "toolu_elsewhere",
		CWD: c.cwd, ToolInput: map[string]any{"file_path": path, "offset": json.Number("45")}}
	c.Observe(context.Background(), elsewhere)
	whole := hook.Event{SessionID: testSession, Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Read", ToolUseID: "toolu_whole",
		CWD: c.cwd, ToolInput: map[string]any{"file_path": path}}
	c.Observe(context.Background(), whole)

	// A Read of the whole file covers the omitted lines too; one from line 45
	// on does not.
	want := []ReadBack{
		{SessionID: testSession, EventID: "evt_bash", ToolUseID: "toolu_cat"},
		{SessionID: testSession, EventID: "evt_read", ToolUseID: "toolu_reread"},
		{SessionID: testSession, EventID: "evt_read", ToolUseID: "toolu_whole"},
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		_, readBacks, _ := c.api.calls()
		if len(readBacks) >= len(want) || time.Now().After(deadline) {
			if !reflect.DeepEqual(readBacks, want) {
				t.Fatalf("read-backs = %+v, want %+v", readBacks, want)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The read-back is not compacted itself.
	reread := c.read(path, content, 25)
	reread.ToolUseID = "toolu_reread"
	reread.ToolInput = map[string]any{"file_path": path, "offset": json.Number("25"), "limit": json.Number("10")}
	if got := c.Compact(context.Background(), reread); got != nil {
		t.Fatal("a read-back was compacted")
	}

	// A restarted daemon still knows the saved output's event.
	restarted := New(Options{Client: c.client, Enabled: c.on.Load, Dir: c.dir, Home: c.home})
	if compaction, ok := restarted.saved(testSession, testToolUseID); !ok || compaction.EventID != "evt_bash" {
		t.Fatalf("restarted lookup = %+v, %v", compaction, ok)
	}
}

func TestCodexShadowNeverBlocksOrChangesTheOutput(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	c := newTestCompactor(t, func(Request) (int, any) {
		<-release
		return http.StatusOK, map[string]any{"decision": "keep", "eventId": testEventID}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx) }()
	t.Cleanup(func() { once.Do(func() { close(release) }); cancel(); <-done })

	output := bigText(80)
	event := hook.Event{SessionID: "codex-019a", Agent: "codex", HookName: hook.HookPostToolUse, ToolName: "Bash", ToolUseID: "call_1",
		CWD: c.cwd, ToolInput: map[string]any{"command": "go test ./..."}, ToolResponse: map[string]any{"content": output}}
	c.Observe(context.Background(), hook.Event{SessionID: "codex-019a", Agent: "codex", HookName: hook.HookUserPromptSubmit,
		ToolInput: map[string]any{"prompt": "fix the failing test"}})
	// The server answers nothing until the test ends: an Observe that waited
	// for it, or for room in a full queue, would not return.
	observed := make(chan struct{})
	go func() {
		defer close(observed)
		for range queueSize + 10 {
			c.Observe(context.Background(), event)
		}
	}()
	select {
	case <-observed:
	case <-time.After(10 * time.Second):
		t.Fatal("Observe blocked on the shadow request")
	}
	if event.ToolResponse["content"] != output {
		t.Fatal("the Codex output was changed")
	}
	if got := c.Compact(context.Background(), event); got != nil {
		t.Fatal("a Codex output was compacted live")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		requests, _, _ := c.api.calls()
		if len(requests) > 0 {
			request := requests[0]
			if request.Mode != ModeShadow || request.Agent != "codex" || request.Output.Kind != KindText || request.Output.Text != output ||
				request.Output.RecoveryPath != "" || request.Context.Goal != "fix the failing test" {
				t.Fatalf("shadow request = %+v", request)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no shadow request was sent")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPruneDeletesSavedOutputsAfterAWeek(t *testing.T) {
	c := newTestCompactor(t, replace("short"))
	now := time.Now()
	c.now = func() time.Time { return now }
	old := filepath.Join(c.dir, "old-session", "toolu_old.txt")
	oldRecord := filepath.Join(c.dir, "old-session", "toolu_old.json")
	fresh := filepath.Join(c.dir, "new-session", "toolu_new.txt")
	for _, path := range []string{old, oldRecord, fresh} {
		if err := writePrivate(c.dir, path, []byte("output")); err != nil {
			t.Fatal(err)
		}
	}
	weekAgo := now.Add(-Retention - time.Minute)
	for _, path := range []string{old, oldRecord} {
		if err := os.Chtimes(path, weekAgo, weekAgo); err != nil {
			t.Fatal(err)
		}
	}
	c.Prune()
	if _, err := os.Stat(filepath.Dir(old)); !os.IsNotExist(err) {
		t.Fatalf("old session directory = %v, want removed", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh output = %v, want kept", err)
	}
}

func TestRequestCarriesTheConversation(t *testing.T) {
	c := newTestCompactor(t, replace("short"))
	transcript := filepath.Join(c.cwd, "session.jsonl")
	rows := []string{
		`{"type":"user","message":{"role":"user","content":"<system-reminder>ignore</system-reminder>Fix the flaky test in pkg/a"}}`,
		`{"type":"assistant","message":{"id":"msg_1","model":"claude-opus-5-5","role":"assistant","content":[{"type":"text","text":"Looking at the test."}]}}`,
		`{"type":"assistant","message":{"id":"msg_1","model":"claude-opus-5-5","role":"assistant","content":[{"type":"tool_use","id":"toolu_a","name":"Read","input":{"file_path":"/repo/pkg/a/a_test.go"}}]}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_a","content":"package a"}]}}`,
		`{"type":"assistant","message":{"id":"msg_s","model":"claude-haiku-5-5","role":"assistant","content":[{"type":"text","text":"subagent row"}]},"isSidechain":true}`,
		`{"type":"assistant","message":{"id":"msg_2","model":"claude-opus-5-5","role":"assistant","content":[{"type":"thinking","thinking":"hmm"},{"type":"text","text":"Running it."}]}}`,
		`{"type":"assistant","message":{"id":"msg_2","model":"claude-opus-5-5","role":"assistant","content":[{"type":"tool_use","id":"` + testToolUseID + `","name":"Bash","input":{"command":"go test ./pkg/a"}}]}}`,
		`{"type":"assistant","message":{"id":"msg_2","model":"claude-opus-5-5","role":"assistant","content":[{"type":"text","text":"Then the log."}]}}`,
	}
	if err := os.WriteFile(transcript, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.Observe(context.Background(), hook.Event{SessionID: testSession, Agent: "claude", HookName: hook.HookUserPromptSubmit,
		ToolInput: map[string]any{"prompt": "Fix the flaky test in pkg/a, then run it"}})
	event := c.bash("go test ./pkg/a", bigText(80))
	event.TranscriptPath = transcript
	if c.Compact(context.Background(), event) == nil {
		t.Fatal("not compacted")
	}
	requests, _, _ := c.api.calls()
	request := requests[0]
	if request.Model == nil || *request.Model != "claude-opus-5-5" {
		t.Fatalf("model = %v", request.Model)
	}
	if request.Context.Goal != "Fix the flaky test in pkg/a, then run it" || request.Context.Current.AssistantText != "Running it.\nThen the log." {
		t.Fatalf("context = %+v", request.Context)
	}
	// The whole transcript was read, so the count is known.
	if request.Context.HistoryLength == nil || *request.Context.HistoryLength != 4 {
		t.Fatalf("historyLength = %v", request.Context.HistoryLength)
	}
	want := []HistoryItem{
		{Role: "user", Content: "Fix the flaky test in pkg/a"},
		{Role: "assistant", Content: "Looking at the test."},
		{Role: "assistant", ToolCalls: []ToolCall{{ID: "toolu_a", Name: "Read", Input: json.RawMessage(`{"file_path":"/repo/pkg/a/a_test.go"}`)}}},
		{Role: "tool", Content: "package a", ToolUseID: "toolu_a"},
	}
	if !reflect.DeepEqual(request.Context.History, want) {
		got, _ := json.Marshal(request.Context.History)
		t.Fatalf("history = %s", got)
	}
}

func TestEncodeDropsHistoryBeforeTheOutput(t *testing.T) {
	request := Request{Output: Output{Kind: KindText, Text: strings.Repeat("o", MaxRequestBytes/2)}}
	for range 8 {
		request.Context.History = append(request.Context.History, HistoryItem{Role: "tool", Content: strings.Repeat("h", MaxRequestBytes/8)})
	}
	body, fits := encode(request)
	if !fits || len(body) > MaxRequestBytes {
		t.Fatalf("encode() = %d bytes, %v", len(body), fits)
	}
	var decoded Request
	if err := json.Unmarshal(body, &decoded); err != nil || len(decoded.Context.History) == 0 || len(decoded.Context.History) == 8 {
		t.Fatalf("history kept = %d, %v", len(decoded.Context.History), err)
	}
	request.Output.Text = strings.Repeat("o", MaxRequestBytes)
	if _, fits := encode(request); fits {
		t.Fatal("an output over the cap fit")
	}
}

// historyLength goes only with a read that reached the start of what the
// model sees; history items are clipped only far above the size of a usual
// item.
func TestHistoryLengthAndClipping(t *testing.T) {
	previous := transcriptTail
	transcriptTail = 4 << 10
	t.Cleanup(func() { transcriptTail = previous })
	write := func(rows ...string) string {
		path := filepath.Join(t.TempDir(), "session.jsonl")
		if err := os.WriteFile(path, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	user := func(text string) string {
		encoded, _ := json.Marshal(text)
		return `{"type":"user","message":{"role":"user","content":` + string(encoded) + `}}`
	}
	call := `{"type":"assistant","message":{"id":"m","model":"claude-opus-5-5","content":[{"type":"tool_use","id":"` + testToolUseID + `","name":"Bash","input":{}}]}}`
	padding := user(strings.Repeat("p", 8<<10))

	event := hook.Event{Agent: "claude", ToolUseID: testToolUseID, TranscriptPath: write(padding, user("one"), user("two"), call)}
	if context, _ := requestContext(event, "goal", "", nil); context.HistoryLength != nil || len(context.History) != 2 {
		t.Fatalf("a partial read sent historyLength %v with %d items", context.HistoryLength, len(context.History))
	}
	event.TranscriptPath = write(padding, `{"type":"system","subtype":"compact_boundary"}`, user("one"), user("two"), call)
	if context, _ := requestContext(event, "goal", "", nil); context.HistoryLength == nil || *context.HistoryLength != 2 {
		t.Fatalf("after a compaction historyLength = %v", context.HistoryLength)
	}

	transcriptTail = previous
	medium, large := strings.Repeat("m", 20<<10), strings.Repeat("l", 70<<10)
	event.TranscriptPath = write(user(medium), user(large), call)
	context, _ := requestContext(event, "goal", "", nil)
	if len(context.History) != 2 || context.History[0].Content != medium || len(context.History[1].Content) > maxHistoryText || !strings.Contains(context.History[1].Content, "[...]") {
		t.Fatalf("history sizes = %d, %d", len(context.History[0].Content), len(context.History[1].Content))
	}
}

// The daemon offers compaction only with the switch on, and only for an
// output it would take up.
func TestOffers(t *testing.T) {
	c := newTestCompactor(t, replace("short"))
	if !c.Offers(c.bash("make test", bigText(80))) {
		t.Fatal("a large Bash output was not offered")
	}
	if c.Offers(c.bash("ls", "small")) {
		t.Fatal("a small output was offered")
	}
	c.on.Store(false)
	if c.Offers(c.bash("make test", bigText(80))) {
		t.Fatal("an output was offered with the switch off")
	}
}

// A call that reads a saved output back stays on the machine: it is not sent
// as the next call's history either.
func TestHistoryLeavesOutSavedOutputReads(t *testing.T) {
	c := newTestCompactor(t, replace("short"))
	saved := filepath.Join(c.dir, testSession, "toolu_old.txt")
	input, _ := json.Marshal(map[string]any{"command": "sed -n 1,99p " + saved})
	transcript := filepath.Join(c.cwd, "session.jsonl")
	rows := []string{
		`{"type":"user","message":{"role":"user","content":"Find the failure"}}`,
		`{"type":"assistant","message":{"id":"m1","model":"claude-opus-5-5","content":[{"type":"tool_use","id":"toolu_back","name":"Bash","input":` + string(input) + `}]}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_back","content":"the saved output"}]}}`,
		`{"type":"assistant","message":{"id":"m2","model":"claude-opus-5-5","content":[{"type":"tool_use","id":"` + testToolUseID + `","name":"Bash","input":{"command":"make test"}}]}}`,
	}
	if err := os.WriteFile(transcript, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	event := c.bash("make test", bigText(80))
	event.TranscriptPath = transcript
	if c.Compact(context.Background(), event) == nil {
		t.Fatal("not compacted")
	}
	requests, _, _ := c.api.calls()
	history := requests[0].Context.History
	if len(history) != 1 || history[0].Content != "Find the failure" {
		got, _ := json.Marshal(history)
		t.Fatalf("history = %s", got)
	}
}

// A read-back the full queue turned away is still reported by the call's
// next hook event, and only once.
func TestReadBackRetriesAfterAFullQueue(t *testing.T) {
	c := newTestCompactor(t, replace("short"))
	if c.Compact(context.Background(), c.bash("make test", bigText(80))) == nil {
		t.Fatal("not compacted")
	}
	for range queueSize {
		c.readBacks <- ReadBack{}
	}
	saved := filepath.Join(c.dir, testSession, testToolUseID+".txt")
	back := hook.Event{SessionID: testSession, Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Bash", ToolUseID: "toolu_back",
		CWD: c.cwd, ToolInput: map[string]any{"command": "cat " + saved}}
	c.Observe(context.Background(), back)
	for range queueSize {
		<-c.readBacks
	}
	back.HookName = hook.HookPostToolUse
	c.Observe(context.Background(), back)
	c.Observe(context.Background(), back)
	if len(c.readBacks) != 1 {
		t.Fatalf("queued read-backs = %d, want 1", len(c.readBacks))
	}
	if got := <-c.readBacks; got.ToolUseID != "toolu_back" || got.EventID != testEventID {
		t.Fatalf("read-back = %+v", got)
	}
}

// After a restart, a read-back goes to the latest compaction of the file,
// whatever the order of the tool use IDs.
func TestRestartKeepsCompactionOrder(t *testing.T) {
	content := bigText(60)
	lines := strings.Split(content, "\n")
	cut := strings.Join(lines[:20], "\n") + "\n[omitted]" + strings.Repeat("\n", 20) + strings.Join(lines[40:], "\n")
	events := 0
	c := newTestCompactor(t, func(Request) (int, any) {
		events++
		return http.StatusOK, map[string]any{"decision": "replace", "eventId": fmt.Sprintf("evt_%d", events), "text": cut}
	})
	now := time.Now()
	c.now = func() time.Time { now = now.Add(time.Second); return now }
	path := filepath.Join(c.cwd, "main.go")
	// Lines 1-60, then 41-100: neither read covers the other's omitted lines.
	// The later compaction has the lexically smaller ID.
	for _, read := range []struct {
		id    string
		start int
	}{{"toolu_b", 1}, {"toolu_a", 41}} {
		event := c.read(path, content, read.start)
		event.ToolUseID = read.id
		event.ToolInput = map[string]any{"file_path": path, "offset": json.Number(strconv.Itoa(read.start))}
		if c.Compact(context.Background(), event) == nil {
			t.Fatalf("%s not compacted", read.id)
		}
	}
	restarted := New(Options{Client: c.client, Enabled: c.on.Load, Dir: c.dir, Home: c.home})
	whole := hook.Event{SessionID: testSession, Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Read", ToolUseID: "toolu_whole",
		ToolInput: map[string]any{"file_path": path}}
	if compaction, ok := restarted.omittedReadBack(whole); !ok || compaction.EventID != "evt_2" {
		t.Fatalf("restarted read-back = %+v, %v, want evt_2", compaction, ok)
	}
}

// Any Read that covers omitted lines reads them back, wherever it starts: it
// is reported, and never cut again.
func TestReadsCoveringOmittedLinesAreReadBacks(t *testing.T) {
	content := bigText(60)
	lines := strings.Split(content, "\n")
	cut := strings.Join(lines[:20], "\n") + "\n[omitted]" + strings.Repeat("\n", 20) + strings.Join(lines[40:], "\n")
	c := newTestCompactor(t, replace(cut))
	path := filepath.Join(c.cwd, "main.go")
	if c.Compact(context.Background(), c.read(path, content, 1)) == nil {
		t.Fatal("not compacted")
	}
	for name, test := range map[string]struct {
		input map[string]any
		want  bool
	}{
		"whole file":          {map[string]any{"file_path": path}, true},
		"from before":         {map[string]any{"file_path": path, "offset": json.Number("10"), "limit": json.Number("20")}, true},
		"inside":              {map[string]any{"file_path": path, "offset": json.Number("30"), "limit": json.Number("5")}, true},
		"ends before":         {map[string]any{"file_path": path, "offset": json.Number("1"), "limit": json.Number("20")}, false},
		"starts after":        {map[string]any{"file_path": path, "offset": json.Number("41")}, false},
		"another file":        {map[string]any{"file_path": path + ".bak"}, false},
		"from before, to end": {map[string]any{"file_path": path, "offset": json.Number("5")}, true},
	} {
		event := c.read(path, content, 1)
		event.ToolUseID = "toolu_again"
		event.ToolInput = test.input
		if got := c.readsBack(event); got != test.want {
			t.Errorf("%s: readsBack = %v, want %v", name, got, test.want)
		}
	}
	again := c.read(path, content, 1)
	again.ToolUseID = "toolu_again"
	if c.Compact(context.Background(), again) != nil {
		t.Fatal("a whole-file re-read was cut again")
	}
}

// A slow install token lookup holds up only its own caller.
func TestTokenLookupKeepsToItsCaller(t *testing.T) {
	stalled := make(chan struct{})
	t.Cleanup(func() { close(stalled) })
	calls := atomic.Int32{}
	client, err := NewClient("https://api.example.test", "ins_test", func(ctx context.Context) (string, error) {
		if calls.Add(1) == 1 {
			select {
			case <-stalled:
			case <-ctx.Done():
			}
			return "", ctx.Err()
		}
		return "install-token", nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = client.installToken(context.Background()) }()
	for calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if token, err := client.installToken(ctx); err != nil || token != "install-token" {
		t.Fatalf("installToken() = %q, %v while another lookup stalls", token, err)
	}
}

// Any spelling of a saved output's path counts: redundant separators, dot
// elements and paths relative to the working directory.
func TestSavedOutputPathSpellings(t *testing.T) {
	c := newTestCompactor(t, replace("short"))
	if c.Compact(context.Background(), c.bash("make test", bigText(80))) == nil {
		t.Fatal("not compacted")
	}
	parent := filepath.Dir(c.dir)
	name := filepath.Join(testSession, testToolUseID+".txt")
	for _, spelling := range []string{
		parent + "//tool-output/" + name,
		parent + "/./tool-output/" + name,
		parent + "/elsewhere/../tool-output/" + name,
		"./tool-output/" + name,
		"sh -c 'tail -n 5 " + parent + "/tool-output/" + name + "'",
	} {
		input := map[string]any{"command": "tail -n 20 " + spelling}
		if !c.namesSaveDir(input, parent) {
			t.Errorf("%q not recognized as the save directory", spelling)
		}
		event := hook.Event{SessionID: testSession, Agent: "claude", HookName: hook.HookPreToolUse, ToolName: "Bash",
			ToolUseID: "toolu_" + strconv.Itoa(len(spelling)), CWD: parent, ToolInput: input}
		c.reportReadBacks(event)
	}
	if len(c.readBacks) != 5 {
		t.Fatalf("read-backs queued = %d, want 5", len(c.readBacks))
	}
}

// An input too large to read in full is not compacted and stays out of
// history: an unread part could name a saved output. Reading it stops at
// the cap instead of splitting all of it.
func TestOversizedInputFailsClosed(t *testing.T) {
	c := newTestCompactor(t, replace("short"))
	huge := strings.Repeat("-x ", maxScanBytes)
	started := time.Now()
	if !c.namesSaveDir(map[string]any{"command": "echo " + huge}, c.cwd) {
		t.Fatal("an input past the scan cap read as not naming the save directory")
	}
	if !c.namesSaveDir(map[string]any{"command": strings.Repeat("a/ ", maxPathWords+1)}, c.cwd) {
		t.Fatal("an input past the path cap read as not naming the save directory")
	}
	if c.Compact(context.Background(), c.bash("echo "+huge, bigText(80))) != nil {
		t.Fatal("a call with an oversized input was compacted")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("scanning took %v", elapsed)
	}
	if c.namesSaveDir(map[string]any{"command": "go test ./..."}, c.cwd) {
		t.Fatal("an ordinary command read as naming the save directory")
	}
}
