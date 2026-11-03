package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/codexproxy"
	"github.com/kontext-security/kontext/internal/codexroute"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hook"
	"github.com/kontext-security/kontext/internal/managedobserve"
)

// Each proxy run logs where Codex's route stands at its first request, and
// again only when that changes.
func TestTheProxyLogsWhereTheRouteStands(t *testing.T) {
	answers := []struct {
		held bool
		err  error
	}{{true, nil}, {true, nil}, {false, nil}, {false, nil}, {false, errors.New("config.toml: permission denied")}, {true, nil}}
	next := 0
	var lines []string
	held := reportHeld(func(context.Context) (bool, error) {
		answer := answers[next]
		next++
		return answer.held, answer.err
	}, func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) })
	for _, answer := range answers {
		if got := held(context.Background()); got != answer.held {
			t.Fatalf("held = %v, want %v", got, answer.held)
		}
	}
	want := []string{
		"Codex route held by a daemon",
		"Codex route not held by a daemon: taken away; passing requests through",
		"Codex route not held by a daemon, and not taken away: config.toml: permission denied",
		"Codex route held by a daemon",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("logged:\n%s", strings.Join(lines, "\n"))
	}
}

// A Codex route the proxy does not answer makes the install unhealthy, in
// the text report, after a repair, and in --json alike.
func TestDoctorCountsAnUnansweredCodexRoute(t *testing.T) {
	managed := managedobserve.DoctorStatus{Healthy: true}
	if !overallHealthy(managed, true, true, true) || overallHealthy(managed, true, true, false) {
		t.Fatal("the Codex route does not count toward a healthy install")
	}
}

// The proxy job logs what came of giving the route up.
func TestTheProxyLogsWhyItGaveTheRouteUp(t *testing.T) {
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	for _, answer := range []struct {
		taken bool
		err   error
	}{{true, nil}, {false, nil}, {false, errors.New("config.toml: permission denied")}} {
		reportUnreachable(func(context.Context) (bool, error) { return answer.taken, answer.err }, logf)(context.Background())
	}
	want := []string{
		"Codex route taken away: requests could not reach the upstream; passing requests through",
		"Codex route left to the daemon changing it, though requests could not reach the upstream",
		"Codex route not taken away, though requests could not reach the upstream: config.toml: permission denied",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("logged:\n%s", strings.Join(lines, "\n"))
	}
}

// Only a Codex session start checks the route, and whatever else the hook
// answers, the person hears what the check found.
func TestACodexSessionStartChecksTheRoute(t *testing.T) {
	checks := 0
	evaluate := withCodexRouteCheck(func(e hook.Event) (hook.Result, error) {
		if e.HookName == hook.HookStop {
			return hook.Result{}, errors.New("daemon said nonsense")
		}
		return hook.FailOpen("managed policy daemon unavailable"), nil
	}, func(context.Context) string {
		checks++
		return codexUnroutedNotice
	})
	result, err := evaluate(hook.Event{Agent: "codex", HookName: hook.HookSessionStart})
	if err != nil || result.Notice != codexUnroutedNotice || !result.FailedOpen || checks != 1 {
		t.Fatalf("a Codex session start = %+v, %v (%d checks)", result, err, checks)
	}
	for _, event := range []hook.Event{
		{Agent: "codex", HookName: hook.HookPreToolUse},
		{Agent: "claude", HookName: hook.HookSessionStart},
		{Agent: "codex", HookName: hook.HookStop},
	} {
		result, err := evaluate(event)
		if result.Notice != "" || checks != 1 || (err != nil) != (event.HookName == hook.HookStop) {
			t.Fatalf("%s %s = %+v, %v (%d checks)", event.Agent, event.HookName, result, err, checks)
		}
	}
}

// A Codex session start hook run in an explicit mode checks the route as the
// managed and sidecar paths do, and its answer says what the check found.
func TestAnExplicitModeCodexSessionStartChecksTheRoute(t *testing.T) {
	previous := codexRouteCheck
	t.Cleanup(func() { codexRouteCheck = previous })
	checks := 0
	codexRouteCheck = func(diagnostic.Logger) func(context.Context) string {
		return func(context.Context) string {
			checks++
			return codexUnroutedNotice
		}
	}
	for _, mode := range []string{"observe", "enforce", "remote"} {
		cmd := hookCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(io.Discard)
		cmd.SetIn(strings.NewReader(`{"session_id":"s1","hook_event_name":"SessionStart","source":"startup","cwd":"/tmp","model":"gpt-6.1-sol","transcript_path":null}`))
		cmd.SetArgs([]string{"--agent", "codex", "--mode", mode, "--socket", filepath.Join(t.TempDir(), "none.sock"), "session-start"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		var answer map[string]any
		if err := json.Unmarshal(out.Bytes(), &answer); err != nil || answer["systemMessage"] != codexUnroutedNotice {
			t.Fatalf("%s: hook answered %s (%v)", mode, out.String(), err)
		}
	}
	if checks != 3 {
		t.Fatalf("%d route checks for 3 session starts", checks)
	}
}

// On a Mac, the hook takes away a route to a port nothing listens on, and
// tells the person to restart Codex; a route that answers stays.
func TestTheSessionStartHookUnroutesARouteNothingAnswers(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Codex is routed through the proxy on macOS only")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("KONTEXT_MANAGED_OBSERVE_DB", filepath.Join(home, "managed-observe", "guard.db"))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	token := strings.Repeat("k", 32)
	original := "model = \"gpt-6.1-sol\"\n"
	routed, err := codexmanaged.AddRoute(original, codexroute.BaseURL(port, token))
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(routed), 0o600); err != nil {
		t.Fatal(err)
	}
	check := unrouteUnansweredCodex(diagnostic.Logger{})
	// A proxy that answers keeps the route.
	proxy := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, codexproxy.HealthBody)
	})}
	go func() { _ = proxy.Serve(listener) }()
	if notice := check(context.Background()); notice != "" {
		t.Fatalf("a route the proxy answers on: %q", notice)
	}
	proxy.Close()
	if notice := check(context.Background()); notice != codexUnroutedNotice {
		t.Fatalf("a route nothing answers on: %q", notice)
	}
	if data, _ := os.ReadFile(configPath); string(data) != original {
		t.Fatalf("config:\n%s", data)
	}
}
