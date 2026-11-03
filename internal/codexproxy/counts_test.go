package codexproxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// counted collects what a proxy counts.
type counted struct {
	mu     sync.Mutex
	counts []Counts
}

func (c *counted) count(counts Counts) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counts = append(c.counts, counts)
}

func (c *counted) take() []Counts {
	c.mu.Lock()
	defer c.mu.Unlock()
	taken := c.counts
	c.counts = nil
	return taken
}

// post sends body to the proxy's responses route as Codex would, with
// userAgent.
func post(t *testing.T, proxy, userAgent string, body []byte) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, proxy+"/"+testToken+"/backend-api/codex/responses", bytes.NewReader(body))
	request.Header.Set("X-Codex-Turn-Metadata", `{"session_id":"s1","thread_id":"t1"}`)
	request.Header.Set("User-Agent", userAgent)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

// Each request counts once what the daemon reports about the route: the
// Codex version it came from; a model request sent on unread, because no
// daemon held the route or its body could not be read; and one whose new
// code mode result held no part at all, which only a change in Codex's format
// makes. A request that connected nowhere counts as an upstream failure.
func TestProxyCountsWhatTheDaemonReports(t *testing.T) {
	const cli = "codex_cli_rs/0.163.0 (Mac OS 26.1.0; arm64) iTerm.app/3.6.1"
	var c counted
	held := true
	var mu sync.Mutex
	proxy, _, _ := newProxyWith(t, Options{Rewriter: newRewriter(t, &fakeDecider{answer: headTail}), Count: c.count,
		Held: func(context.Context) bool {
			mu.Lock()
			defer mu.Unlock()
			return held
		}})
	drifted := map[string]any{"type": "custom_tool_call_output", "call_id": "call_1",
		"output": []map[string]any{{"type": "input_text", "content": "Script completed\nOutput:\n"}, {"type": "input_text", "content": seq(1, 3000)}}}
	for _, step := range []struct {
		name      string
		userAgent string
		body      []byte
		unheld    bool
		want      Counts
	}{
		{"a part to shorten", cli, body(t, user("go"), call("call_1", "text(1)"), result("call_1", seq(1, 3000))), false,
			Counts{CodexVersion: "0.163.0"}},
		{"a script that printed nothing", "Codex Desktop/0.163.0-alpha.11 (Mac OS 26.1.0; arm64) unknown",
			body(t, user("go"), call("call_1", "text(1)"), result("call_1")), false, Counts{CodexVersion: "0.163.0-alpha.11"}},
		{"a call the person interrupted", cli, body(t, user("go"), call("call_1", "text(1)"),
			map[string]any{"type": "custom_tool_call_output", "call_id": "call_1", "output": "aborted"}), false, Counts{CodexVersion: "0.163.0"}},
		{"a format the proxy finds no part in", cli, body(t, user("go"), call("call_1", "text(1)"), drifted), false,
			Counts{PartsMissing: 1, CodexVersion: "0.163.0"}},
		{"that format, answered since", cli, body(t, user("go"), call("call_1", "text(1)"), drifted, assistant("done"), user("more")), false,
			Counts{CodexVersion: "0.163.0"}},
		{"a body that does not parse", "", []byte(`{"input": [`), false, Counts{PassThroughs: 1}},
		{"no daemon holds the route", cli, body(t, user("go"), call("call_1", "text(1)"), drifted), true,
			Counts{PassThroughs: 1, CodexVersion: "0.163.0"}},
	} {
		mu.Lock()
		held = !step.unheld
		mu.Unlock()
		post(t, proxy.URL, step.userAgent, step.body)
		if got := c.take(); len(got) != 1 || got[0] != step.want {
			t.Fatalf("%s: counted %+v, want %+v", step.name, got, step.want)
		}
	}

	old := bodyLimit
	bodyLimit = 64
	defer func() { bodyLimit = old }()
	post(t, proxy.URL, cli, body(t, user(strings.Repeat("x", 128))))
	if got := c.take(); len(got) != 1 || got[0] != (Counts{PassThroughs: 1, CodexVersion: "0.163.0"}) {
		t.Fatalf("an oversized body counted %+v", got)
	}
}

func TestProxyCountsEachRequestThatConnectedNowhere(t *testing.T) {
	var c counted
	address := refusing(t)
	upstream, _ := url.Parse(address + "/backend-api/codex")
	apiUpstream, _ := url.Parse(address + "/v1")
	server, err := New(Options{Upstream: upstream, APIUpstream: apiUpstream, Token: testToken, Count: c.count})
	if err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(server)
	defer proxy.Close()
	for range 2 {
		response, err := http.Get(proxy.URL + "/" + testToken + "/backend-api/codex/models")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	// The breaker counts each failure, then the request counts what else
	// it found.
	got := c.take()
	if len(got) != 4 || got[0] != (Counts{UpstreamFailures: 1}) || got[2] != (Counts{UpstreamFailures: 1}) || got[1] != (Counts{}) || got[3] != (Counts{}) {
		t.Fatalf("counted %+v", got)
	}
}

func TestCodexVersionIsWhatFollowsTheFirstSlash(t *testing.T) {
	for userAgent, want := range map[string]string{
		"codex_cli_rs/0.166.0 (Mac OS 26.1.0; arm64) Apple_Terminal/455.1": "0.166.0",
		"Codex Desktop/0.163.0-alpha.11 (Mac OS 26.5.0; arm64) unknown":    "0.163.0-alpha.11",
		"codex_exec/0.163.0":                    "0.163.0",
		"codex_work_desktop/1.2.3+build.7 (…)":  "1.2.3+build.7",
		"":                                      "",
		"codex":                                 "",
		"codex/ (Mac OS)":                       "",
		"codex/latest (Mac OS)":                 "",
		"codex/0.1.0;rm -rf (Mac OS)":           "",
		"codex/" + strings.Repeat("1", 33) + "": "",
		"Go-http-client/1.1":                    "",
		"curl/8.7.1":                            "",
	} {
		if got := codexVersion(userAgent); got != want {
			t.Errorf("codexVersion(%q) = %q, want %q", userAgent, got, want)
		}
	}
}

// Only a new code mode result counts as missing its parts: one answered
// before was counted then, and other tools' results have no framing.
func TestRewriteCountsOnlyNewCodeModeResultsWithNoPart(t *testing.T) {
	rw := newRewriter(t, &fakeDecider{answer: headTail})
	empty := func(callID string) map[string]any {
		return map[string]any{"type": "custom_tool_call_output", "call_id": callID, "output": []map[string]any{}}
	}
	patch := map[string]any{"type": "custom_tool_call", "call_id": "call_9", "name": "apply_patch", "input": "*** Begin Patch"}
	for name, test := range map[string]struct {
		body []byte
		want int
	}{
		"one new":            {body(t, user("go"), call("call_1", "text(1)"), empty("call_1")), 1},
		"two new":            {body(t, user("go"), call("call_1", "text(1)"), call("call_2", "text(2)"), empty("call_1"), empty("call_2")), 2},
		"one answered since": {body(t, user("go"), call("call_1", "text(1)"), empty("call_1"), assistant("done"), user("more")), 0},
		"another tool":       {body(t, user("go"), patch, empty("call_9")), 0},
		"framed and silent":  {body(t, user("go"), call("call_1", "text(1)"), result("call_1")), 0},
	} {
		_, stats, err := rw.Rewrite(context.Background(), Identity{SessionID: "s-" + name}, test.body)
		if err != nil || stats.PartsMissing != test.want {
			t.Errorf("%s: PartsMissing = %d, %v; want %d", name, stats.PartsMissing, err, test.want)
		}
	}
}
