package tooloutput

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/modelusage"
)

// secretOutput is an env dump with a secret on most of its first lines, a
// private key among them, and lines with none after them. secretsIn lists
// what must stay on the device.
func secretOutput() string {
	return "$ env | sort\n" +
		"AWS_ACCESS_KEY_ID=AKIAFAKEFAKEFAKEFAKE\n" +
		"DATABASE_URL=postgres://app:hunter2FAKEpass@db.example.test/app\n" +
		"DB_PASSWORD=db-secret-FAKE\n" +
		"GITHUB_TOKEN=ghp_FAKE0123456789abcdefFAKE\n" +
		"OPENAI_API_KEY=sk-proj-FAKEabcdefghijklmnop1234\n" +
		"SESSION eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.FAKEsignatureFAKE1234\n" +
		"-----BEGIN RSA PRIVATE KEY-----\nMIIfakekeymaterialFAKE\nMIIsecondkeylineFAKE\n-----END RSA PRIVATE KEY-----\n" +
		bigText(60)
}

var secretsIn = []string{
	"AKIAFAKEFAKEFAKEFAKE", "hunter2FAKEpass", "db-secret-FAKE", "ghp_FAKE0123456789abcdefFAKE", "sk-proj-FAKEabcdefghijklmnop1234",
	"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.FAKEsignatureFAKE1234", "MIIfakekeymaterialFAKE", "MIIsecondkeylineFAKE",
}

// secretsAnd is secretsIn and more.
func secretsAnd(more ...string) []string {
	return append(append([]string(nil), secretsIn...), more...)
}

// ends is what the server answers with: lines of what it was sent, the
// first and the last few, around a note naming the saved output.
func ends(text string, first, last int, path string) string {
	lines := strings.Split(text, "\n")
	return strings.Join(lines[:first], "\n") + "\n[lines omitted; full output: " + path + "]\n" + strings.Join(lines[len(lines)-last:], "\n")
}

func keepEnds(first, last int) func(Request) (int, any) {
	return func(request Request) (int, any) {
		text := ends(request.Output.Text, first, last, request.Output.RecoveryPath)
		return http.StatusOK, map[string]any{"decision": "replace", "eventId": testEventID, "text": text}
	}
}

// sent returns every request body as sent.
func (a *fakeAPI) sent() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.bodies...)
}

func assertNoneSent(t *testing.T, api *fakeAPI, secrets []string) {
	t.Helper()
	bodies := api.sent()
	if len(bodies) == 0 {
		t.Fatal("nothing was sent")
	}
	for _, body := range bodies {
		for _, secret := range secrets {
			if strings.Contains(body, secret) {
				t.Fatalf("secret %q was sent: %s", secret, body)
			}
		}
	}
}

func TestSecretsStayOnTheDevice(t *testing.T) {
	c := newTestCompactor(t, keepEnds(10, 3))
	transcript := filepath.Join(c.cwd, "session.jsonl")
	rows := []string{
		`{"type":"user","message":{"role":"user","content":"Deploy it, the npm token is npm_FAKEabcdefghijklmnop12"}}`,
		`{"type":"assistant","message":{"id":"msg_1","model":"claude-opus-5-5","role":"assistant","content":[{"type":"text","text":"Calling the API with key AIzaFAKE1234567890abcdefghij."}]}}`,
		`{"type":"assistant","message":{"id":"msg_1","model":"claude-opus-5-5","role":"assistant","content":[{"type":"tool_use","id":"toolu_a","name":"Bash","input":{"command":"curl -H 'Authorization: Bearer FAKEbearer0123456789' https://api.example.test","api_key":"FAKEinputvalue123"}}]}}`,
		`{"type":"user","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_a","content":"slack said xoxb-FAKE123456-FAKEabcdefghij"}]}}`,
		`{"type":"assistant","message":{"id":"msg_2","model":"claude-opus-5-5","role":"assistant","content":[{"type":"text","text":"Checking the env, password=FAKEassistantpass."}]}}`,
		`{"type":"assistant","message":{"id":"msg_2","model":"claude-opus-5-5","role":"assistant","content":[{"type":"tool_use","id":"` + testToolUseID + `","name":"Bash","input":{"command":"env | sort"}}]}}`,
	}
	if err := os.WriteFile(transcript, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.Observe(context.Background(), hook.Event{SessionID: testSession, Agent: "claude", HookName: hook.HookUserPromptSubmit,
		ToolInput: map[string]any{"prompt": "Deploy with github_pat_11FAKEFAKE0123456789abcdef please"}})
	output := secretOutput()
	event := c.bash("SLACK_TOKEN=FAKEcommandtoken env | sort", output)
	event.TranscriptPath = transcript

	got := c.Compact(context.Background(), event)
	saved := filepath.Join(c.dir, testSession, testToolUseID+".txt")
	if got == nil || got["stdout"] != ends(output, 10, 3, saved) {
		t.Fatalf("Compact() = %#v, want the output's first 10 and last 2 lines", got)
	}
	assertNoneSent(t, c.api, secretsAnd("npm_FAKEabcdefghijklmnop12", "AIzaFAKE1234567890abcdefghij", "FAKEbearer0123456789",
		"FAKEinputvalue123", "xoxb-FAKE123456-FAKEabcdefghij", "FAKEassistantpass", "github_pat_11FAKEFAKE0123456789abcdef", "FAKEcommandtoken"))

	requests, _, _ := c.api.calls()
	request := requests[0]
	if strings.Count(request.Output.Text, "\n") != strings.Count(output, "\n") || !strings.HasSuffix(request.Output.Text, bigText(60)) {
		t.Fatalf("sent output does not keep the output's lines: %q", request.Output.Text)
	}
	// Redacted, not dropped: the server still sees what the call was about.
	if request.Context.Goal != "Deploy with [REDACTED_SECRET] please" || len(request.Context.History) != 4 ||
		request.Context.History[0].Content != "Deploy it, the npm token is [REDACTED_SECRET]" ||
		request.Context.Current.AssistantText != "Checking the env, password=[REDACTED_SECRET]" {
		t.Fatalf("context = %+v", request.Context)
	}
	if input, _ := request.ToolInput.(map[string]any); input["command"] != "SLACK_TOKEN=[REDACTED_SECRET] env | sort" || input["description"] != "Run the tests" {
		t.Fatalf("tool input = %#v", request.ToolInput)
	}
	if data, err := os.ReadFile(saved); err != nil || string(data) != output {
		t.Fatalf("saved output = %q, %v; want the output as it was", data, err)
	}
}

func TestReadKeepsTheLinesItShowsAroundSecrets(t *testing.T) {
	content := secretOutput()
	// Lines 21-40 become one note and padding, as the server answers a Read.
	omit := func(text string) string {
		lines := strings.Split(text, "\n")
		return strings.Join(lines[:20], "\n") + "\n[omitted lines 21-40]" + strings.Repeat("\n", 20) + strings.Join(lines[40:], "\n")
	}
	c := newTestCompactor(t, func(request Request) (int, any) {
		return http.StatusOK, map[string]any{"decision": "replace", "eventId": testEventID, "text": omit(request.Output.Text)}
	})
	path := filepath.Join(c.cwd, "config", "password=FAKEpathsecret", "app.env")
	got := c.Compact(context.Background(), c.read(path, content, 1))
	if got == nil {
		t.Fatal("Compact() = nil, want a replacement")
	}
	if file := got["file"].(map[string]any); file["content"] != omit(content) || file["filePath"] != path {
		t.Fatalf("rebuilt file = %#v", file)
	}
	assertNoneSent(t, c.api, secretsAnd("FAKEpathsecret"))
	if records := c.sessions[testSession].records; len(records) != 1 || !reflect.DeepEqual(records[0].Omitted, [][2]int{{21, 40}}) || records[0].FilePath != path {
		t.Fatalf("records = %+v", records)
	}
}

func TestLiveCodexKeepsSecretsOnTheDevice(t *testing.T) {
	c := newTestCompactor(t, keepEnds(10, 3))
	log := c.codexLog(t,
		`{"type":"turn_context","payload":{"model":"gpt-5.5"}}`,
		`{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"Use token=FAKEcodexprompt to deploy"}]}}`,
		codexCall("exec_command", "call_1"), codexExited("call_1", 1))
	output := secretOutput()
	got := c.Compact(context.Background(), c.codex(log, output))
	saved := filepath.Join(c.dir, "codex-019a", "call_1.txt")
	if want := "Process exited with code 1\n" + ends(output, 10, 3, saved); got == nil || got["content"] != want {
		t.Fatalf("Compact() = %#v", got)
	}
	assertNoneSent(t, c.api, secretsAnd("FAKEcodexprompt"))
}

func TestProxiedPartKeepsSecretsOnTheDevice(t *testing.T) {
	c := newTestCompactor(t, keepEnds(10, 3))
	quote := func(text string) string {
		data, _ := json.Marshal(text)
		return string(data)
	}
	script := `const key = "sk-proj-FAKEscript0123456789ab"; text(await tools.exec_command({cmd: "env | sort"}))`
	printed := secretOutput()
	items := []string{
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"deploy with password: FAKEproxyprompt"}]}`,
		`{"type":"function_call","name":"exec_command","arguments":` + quote(`{"cmd":"curl -u admin:FAKEcurlsecret https://api.example.test"}`) + `,"call_id":"call_0"}`,
		`{"type":"function_call_output","call_id":"call_0","output":"token=FAKEearlieroutput ok"}`,
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"Now with ghs_FAKEassistant0123456789."}]}`,
		`{"type":"custom_tool_call","call_id":"call_1","name":"exec","input":` + quote(script) + `}`,
		`{"type":"custom_tool_call_output","call_id":"call_1","output":[{"type":"input_text","text":"Script completed\nOutput:\n"},{"type":"input_text","text":` + quote(printed) + `}]}`,
	}
	raw := make([]json.RawMessage, len(items))
	for i, item := range items {
		raw[i] = json.RawMessage(item)
	}
	out := ProxyOutput{SessionID: "codex-019a", CallID: "call_1", Part: 1, ToolName: "exec", ToolInput: script,
		Model: "gpt-6.1-sol", CWD: c.cwd, Text: printed, Conversation: modelusage.CodexItemsConversation(raw), Whole: true}

	text, ok := c.CompactProxied(context.Background(), out)
	saved := filepath.Join(c.dir, "codex-019a", "call_1-1.txt")
	if !ok || text != ends(printed, 10, 3, saved) {
		t.Fatalf("CompactProxied = %q, %v", text, ok)
	}
	assertNoneSent(t, c.api, secretsAnd("sk-proj-FAKEscript0123456789ab", "FAKEproxyprompt", "FAKEcurlsecret", "FAKEearlieroutput", "ghs_FAKEassistant0123456789"))
	requests, _, _ := c.api.calls()
	if history := requests[0].Context.History; len(history) != 3 || len(history[1].ToolCalls) != 1 || !strings.Contains(string(history[1].ToolCalls[0].Input), "[REDACTED_SECRET]") {
		t.Fatalf("history = %+v", history)
	}
	if again, ok := c.CompactProxied(context.Background(), out); !ok || again != text {
		t.Fatalf("second ask = %q, %v; want the same shorter text", again, ok)
	}
}

var sentPlaceholder = regexp.MustCompile("\u27e6REDACTED_SECRET_[0-9]+\u27e7")

// A placeholder the answer cuts short or changes means the answer is not
// made of the output's lines, so the output stays as it is, on either path.
func TestDamagedPlaceholdersLeaveTheOutput(t *testing.T) {
	for name, damage := range map[string]func(sent string) string{
		"cut short": func(sent string) string {
			at := sentPlaceholder.FindStringIndex(sent)
			return sent[:at[0]+len("\u27e6RED")] + "\n[the rest omitted]\n"
		},
		"cut at the start": func(sent string) string {
			at := sentPlaceholder.FindStringIndex(sent)
			return "[the start omitted]\n" + sent[at[1]-len("ET_1\u27e7"):]
		},
		"unknown number": func(sent string) string {
			return sentPlaceholder.ReplaceAllString(sent[:len(sent)/2], "\u27e6REDACTED_SECRET_999\u27e7")
		},
		"renamed": func(sent string) string {
			return strings.Replace(sent[:len(sent)/2], "REDACTED_SECRET_1", "REDACTED_SECRET_01", 1)
		},
		"stray delimiter": func(sent string) string {
			return sent[:len(sent)/2] + "\u27e7"
		},
		"repeated": func(sent string) string {
			return strings.Repeat(sentPlaceholder.FindString(sent)+"\n", 1000)
		},
	} {
		t.Run(name, func(t *testing.T) {
			reply := func(request Request) (int, any) {
				return http.StatusOK, map[string]any{"decision": "replace", "eventId": testEventID, "text": damage(request.Output.Text)}
			}
			c := newTestCompactor(t, reply)
			if got := c.Compact(context.Background(), c.bash("env", secretOutput())); got != nil {
				t.Fatalf("Compact() = %#v, want the output left as is", got)
			}
			if entries, _ := os.ReadDir(filepath.Join(c.dir, testSession)); len(entries) != 0 {
				t.Fatalf("saved %v for an output left as is", entries)
			}
			p := newTestCompactor(t, reply)
			if text, ok := p.CompactProxied(context.Background(), p.proxyOutput("text(1)", secretOutput())); ok {
				t.Fatalf("CompactProxied = %q, want the part left as is", text)
			}
		})
	}
}

// The agent is shown the path of the saved output as the server got it, so
// an output saved under a path with a secret in it is not sent at all.
func TestSecretInTheSavePathKeepsTheOutput(t *testing.T) {
	c := newTestCompactor(t, keepEnds(10, 3))
	c.Compactor = New(Options{Client: c.client, Enabled: c.on.Load, Dir: filepath.Join(t.TempDir(), "password=FAKEdirsecret", "tool-output"), Home: c.home})
	if got := c.Compact(context.Background(), c.bash("env", secretOutput())); got != nil {
		t.Fatalf("Compact() = %#v, want the output left as is", got)
	}
	if text, ok := c.CompactProxied(context.Background(), c.proxyOutput("text(1)", secretOutput())); ok {
		t.Fatalf("CompactProxied = %q, want the part left as is", text)
	}
	if _, _, sent := c.api.calls(); sent != 0 {
		t.Fatalf("%d requests sent", sent)
	}
}

func TestHideSecretsKeepsTheLines(t *testing.T) {
	t.Parallel()

	output := secretOutput()
	hidden, found, err := hideSecrets(output)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range secretsIn {
		if strings.Contains(hidden, secret) {
			t.Fatalf("secret %q survives in %q", secret, hidden)
		}
	}
	sent, original := strings.Split(hidden, "\n"), strings.Split(output, "\n")
	if len(sent) != len(original) {
		t.Fatalf("%d lines sent for %d", len(sent), len(original))
	}
	for i := range original {
		if !strings.Contains(sent[i], "\u27e6") && sent[i] != original[i] {
			t.Fatalf("line %d without a secret changed: %q, was %q", i+1, sent[i], original[i])
		}
	}
	// Each line restores alone, so any choice of lines restores.
	for i := range sent {
		if line, err := found.reveal(sent[i], len(output)); err != nil || line != original[i] {
			t.Fatalf("line %d restores as %q, %v; want %q", i+1, line, err, original[i])
		}
	}
	if whole, err := found.reveal(hidden, len(output)+1); err != nil || whole != output {
		t.Fatalf("reveal = %q, %v", whole, err)
	}
	if found.open != "\u27e6" || len(found.values) != 10 {
		t.Fatalf("delimiters %q, %d secrets", found.open, len(found.values))
	}
}

func TestHideSecretsUsesFreeDelimiters(t *testing.T) {
	t.Parallel()

	secret := "token=FAKEvalue123"
	for _, test := range []struct {
		name   string
		text   string
		echoed []string
		open   string // "" means no pair is free
	}{
		{"none taken", secret, nil, "\u27e6"},
		{"first taken", secret + " \u27e7", nil, "\u2983"},
		{"first echoed", secret, []string{"/home/\u27e6/saved.txt"}, "\u2983"},
		{"all taken", secret + " \u27e6 \u2984 \u27ed", nil, ""},
	} {
		hidden, found, err := hideSecrets(test.text, test.echoed...)
		if test.open == "" && !errors.Is(err, errDelimiters) || test.open != "" && (err != nil || found.open != test.open || strings.Contains(hidden, "FAKEvalue123")) {
			t.Errorf("%s: hideSecrets = %q, %+v, %v", test.name, hidden, found, err)
		}
	}
	// An output without secrets needs no delimiters at all.
	if hidden, found, err := hideSecrets("\u27e6 \u2984 \u27ed plain"); err != nil || hidden != "\u27e6 \u2984 \u27ed plain" {
		t.Errorf("plain text: %q, %+v, %v", hidden, found, err)
	} else if text, err := found.reveal("\u27e6 kept", 100); err != nil || text != "\u27e6 kept" {
		t.Errorf("reveal without secrets = %q, %v", text, err)
	}
}

// An answer that repeats a placeholder could reveal into a text far larger
// than the answer; reveal stops at the output's length before building it.
func TestRevealStopsAtTheOutputsLength(t *testing.T) {
	t.Parallel()

	output := `password="` + strings.Repeat("x", 512<<10) + "\n" + bigText(10)
	hidden, found, err := hideSecrets(output)
	if err != nil || len(found.values) == 0 || len(found.values[0]) < 512<<10 {
		t.Fatalf("hideSecrets = %d bytes, %v", len(hidden), err)
	}
	// About 1.3 MB, within what the client reads; about 30 GB revealed.
	answer := strings.Repeat(sentPlaceholder.FindString(hidden)+"\n", 60_000)
	if text, err := found.reveal(answer, len(output)); !errors.Is(err, errNoShorter) {
		t.Fatalf("reveal = %d bytes, %v; want %v", len(text), err, errNoShorter)
	}
	if text, err := found.reveal(hidden, len(output)); !errors.Is(err, errNoShorter) {
		t.Fatalf("reveal of the whole output = %d bytes, %v; want %v", len(text), err, errNoShorter)
	}
}

// Context is redacted within a budget, its newest history first, and a text
// past what is left of it is left out: never cut before it is redacted.
func TestContextIsRedactedWithinABudget(t *testing.T) {
	t.Parallel()

	result := func(id string, size int) modelusage.Message {
		return modelusage.Message{Role: "tool", ToolUseID: id, Text: "password=FAKE" + id + "secret " + strings.Repeat("y", size)}
	}
	call := func(id, response string, input string) modelusage.Message {
		return modelusage.Message{Role: "assistant", Response: response, ToolCall: &modelusage.ToolCall{ID: id, Name: "exec", Input: json.RawMessage(input)}}
	}
	huge := `{"content":"` + strings.Repeat("z", maxRedacted) + `"}`
	conversation := modelusage.Conversation{Messages: []modelusage.Message{
		{Role: "user", Text: "deploy it", Prompt: true},
		call("c1", "r1", `{"cmd":"cat old.log"}`),
		result("c1", maxRedacted/2),
		call("c2", "r2", huge),
		result("c2", maxRedacted/2),
		call("c3", "r3", `{"cmd":"cat new.log"}`),
	}}
	context := conversationContext(conversation, true, "token=FAKEgoalsecret deploy", "c3", "exec", "text(1)", nil)
	if context.Goal != "token=[REDACTED_SECRET] deploy" {
		t.Fatalf("goal = %q", context.Goal)
	}
	history := context.History
	if len(history) != 5 {
		t.Fatalf("history = %d items", len(history))
	}
	// Newest first: the second result fits, the call before it, too large
	// for what is left, and the older result are left out.
	if got := history[4].Content; !strings.HasPrefix(got, "password=[REDACTED_SECRET] yyy") || len(got) > maxHistoryText {
		t.Fatalf("newest result = %d bytes starting %.40q", len(got), got)
	}
	if string(history[3].ToolCalls[0].Input) != `"[...]"` || history[2].Content != leftOut {
		t.Fatalf("older items = %.40q, %.40q", history[3].ToolCalls[0].Input, history[2].Content)
	}
	if string(history[1].ToolCalls[0].Input) != `{"cmd":"cat old.log"}` || history[0].Content != "deploy it" {
		t.Fatalf("small items = %s, %q", history[1].ToolCalls[0].Input, history[0].Content)
	}
	data, _ := json.Marshal(context)
	for _, secret := range []string{"FAKEc1secret", "FAKEc2secret", "FAKEgoalsecret"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("secret %q sent", secret)
		}
	}
}

func TestRedactedJSON(t *testing.T) {
	t.Parallel()

	for _, test := range []struct{ raw, want string }{
		{`{"command":"ls","b":1.50}`, `{"command":"ls","b":1.50}`},
		{`{"password":"FAKEpw","n":1.50,"cmd":"GITHUB_TOKEN=ghp_FAKE0123456789abcdefFAKE"}`, `{"cmd":"GITHUB_TOKEN=[REDACTED_SECRET]","n":1.50,"password":"[REDACTED_SECRET]"}`},
		{`"curl -u admin:FAKEpw https://x.test"`, `"curl -u [REDACTED_SECRET] https://x.test"`},
		{`{"token":`, `"{\"token\":"`},
		{`{"a":1} {"token":"FAKEpw"}`, `"{\"a\":1} {\"token\":\"[REDACTED_SECRET]\"}"`},
	} {
		if got := string(redactedJSON(json.RawMessage(test.raw))); got != test.want {
			t.Errorf("redactedJSON(%s) = %s, want %s", test.raw, got, test.want)
		}
	}
}

func BenchmarkHideAndReveal(b *testing.B) {
	for name, line := range map[string]string{
		"log":     "2026-11-03T10:00:00.123Z INFO server/handler.go:120 request id=%08x path=/api/v1/items status=200 took=12ms\n",
		"secrets": "API_KEY_%08x=sk-proj-FAKEabcdefghijklmnop%d\nPATH=/usr/bin:/bin\n",
	} {
		var output strings.Builder
		for i := 0; output.Len() < 1<<20; i++ {
			fmt.Fprintf(&output, line, i, i)
		}
		text := output.String()[:1<<20]
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(text)))
			for b.Loop() {
				hidden, found, err := hideSecrets(text)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := found.reveal(hidden, len(text)+1); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
