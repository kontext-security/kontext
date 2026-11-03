package codexroute

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/codexmanaged"
)

// oldBuild fails as a kontext build without the proxy does.
const oldBuild = "#!/bin/sh\necho 'Error: unknown command \"codex-proxy\" for \"kontext\"' >&2\nexit 1\n"

// TestRealLaunchdJob loads the proxy's job into launchd, under a label of its
// own, from a temporary home. It checks the proxy answers through socket
// activation, that the daemon reloads the job an older build left loaded,
// that the proxy still answers once a downgrade replaced the daemon's binary
// and a cleanup deleted it, sends an API key's request to the OpenAI API, and
// takes Codex's route away itself once no daemon holds it; then it takes it
// all away again. It needs a built kontext binary,
// sends nothing off the machine, and never touches ~/.codex or a job already
// loaded. Opt in with KONTEXT_LAUNCHD_E2E_BIN=/path/to/kontext (see
// scripts/codex-proxy-e2e.sh).
func TestRealLaunchdJob(t *testing.T) {
	built := os.Getenv("KONTEXT_LAUNCHD_E2E_BIN")
	if built == "" {
		t.Skip("set KONTEXT_LAUNCHD_E2E_BIN to a kontext binary to run")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("launchd is macOS only")
	}
	home, err := os.MkdirTemp("/tmp", "kx-launchd-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	writeFile(t, filepath.Join(home, ".codex", "auth.json"), authFor("plus"), 0o600)
	writeFile(t, filepath.Join(home, ".codex", "config.toml"), original, 0o600)
	// The daemon's binary, where an update or a downgrade replaces it.
	installed := filepath.Join(home, "install", "kontext")
	data, err := os.ReadFile(built)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, installed, string(data), 0o755)
	binary, err := os.Open(installed)
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()

	var mu sync.Mutex
	var forwarded []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entry := r.Method + " " + r.URL.Path
		if r.Header.Get("Authorization") != "" {
			entry += " (signed)"
		}
		mu.Lock()
		forwarded = append(forwarded, entry)
		mu.Unlock()
		_, _ = io.WriteString(w, "{}")
	}))
	defer upstream.Close()

	label := Label + ".test-" + strconv.Itoa(os.Getpid())
	domain := "gui/" + strconv.Itoa(os.Getuid()) + "/" + label
	stateDir, socket := filepath.Join(home, "state"), filepath.Join(home, "no-daemon.sock")
	// What the router asked launchctl, and what it said, for a failure.
	var launchctlMu sync.Mutex
	var launchctl []string
	run := func(ctx context.Context, args ...string) error {
		err := runLaunchctl(ctx, args...)
		launchctlMu.Lock()
		launchctl = append(launchctl, fmt.Sprintf("%s %s: %v", args[0], args[len(args)-1], err))
		launchctlMu.Unlock()
		return err
	}
	ran := func() string {
		launchctlMu.Lock()
		defer launchctlMu.Unlock()
		return strings.Join(launchctl, "\n")
	}
	router := New(Options{Home: home, Binary: binary, StateDir: stateDir, Socket: socket, Launchctl: run,
		Label: label, Upstream: upstream.URL + "/backend-api/codex", APIUpstream: upstream.URL + "/v1",
		// Codex processes running on this Mac never read this home's config.
		CodexSince: func(time.Time) (int, error) { return 0, nil }})
	ctx := context.Background()
	defer func() {
		if _, err := router.Remove(ctx, 0); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	}()
	logOnFailure := func() string {
		log, _ := os.ReadFile(filepath.Join(home, "Library", "Logs", "Kontext", "codex-proxy.log"))
		return string(log)
	}

	status, err := router.Enable(ctx)
	if err != nil || !status.Routed || !status.Loaded {
		t.Fatalf("Enable = %+v, %v\nproxy log:\n%s", status, err, logOnFailure())
	}
	// Before Codex was routed, the job reached the upstream, with no
	// credentials.
	mu.Lock()
	reached := strings.Join(forwarded, ", ")
	forwarded = nil
	mu.Unlock()
	if reached != "HEAD /backend-api/codex" {
		t.Fatalf("before Codex was routed, the upstream saw %q", reached)
	}
	if info, err := os.Stat(router.plistPath()); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("plist mode = %v, %v", info.Mode().Perm(), err)
	}
	config, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml"))
	if !strings.HasPrefix(codexmanaged.Route(string(config)), "http://127.0.0.1:"+strconv.Itoa(status.Port)+"/kx") {
		t.Fatalf("config:\n%s", config)
	}
	if status := router.Status(ctx); !status.Answering {
		t.Fatalf("Status = %+v", status)
	}

	// An older build left Codex routed: its job runs the daemon's binary in
	// place, without --home (and here with the test's upstreams, so nothing
	// leaves the machine), and route.json names no holder and no copy. A
	// proxy runs from that job, as for a Codex already routed. The daemon
	// keeps the line and reloads the job, from its own copy.
	older := job{label: label, port: status.Port, home: home, stateDir: stateDir, socket: socket,
		upstream: upstream.URL + "/backend-api/codex", apiUpstream: upstream.URL + "/v1", logPath: router.logPath()}
	writeFile(t, router.plistPath(), olderPlist(older, installed), 0o644)
	if err := router.unloadJob(ctx); err != nil {
		t.Fatal(err)
	}
	if err := runLaunchctl(ctx, "bootstrap", "gui/"+strconv.Itoa(os.Getuid()), router.plistPath()); err != nil {
		t.Fatal(err)
	}
	st := router.loadState()
	st.Holder, st.Binary = nil, ""
	if err := router.saveState(st); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Dir(BinaryPath(stateDir))); err != nil {
		t.Fatal(err)
	}
	if status := router.Status(ctx); !status.Answering {
		t.Fatalf("the older build's job: Status = %+v\nproxy log:\n%s", status, logOnFailure())
	}
	if status, err := router.Enable(ctx); err != nil || !status.Answering {
		t.Fatalf("Enable over the older build's job = %+v, %v; launchctl ran:\n%s", status, err, ran())
	}
	if now, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml")); string(now) != string(config) {
		t.Fatalf("the line changed:\n%s", now)
	}
	printed, err := exec.Command("/bin/launchctl", "print", domain).Output()
	if err != nil || !strings.Contains(string(printed), "program = "+BinaryPath(stateDir)+"\n") || !strings.Contains(string(printed), "\t\t--home\n") {
		t.Fatalf("launchd's job after the reload (%v):\n%s", err, printed)
	}

	// A downgrade puts a build without the proxy where the daemon's binary
	// was, and a cleanup deletes it: launchd still starts the proxy, from
	// the job's own copy.
	for name, change := range map[string]func() error{
		"downgrade": func() error {
			writeFile(t, installed+".old", oldBuild, 0o755)
			return os.Rename(installed+".old", installed)
		},
		"cleanup": func() error { return os.Remove(installed) },
	} {
		if err := change(); err != nil {
			t.Fatal(err)
		}
		// The proxy running now exits, so the next connection starts one.
		_ = exec.Command("/bin/launchctl", "kill", "TERM", domain).Run()
		time.Sleep(500 * time.Millisecond)
		if status := router.Status(ctx); !status.Answering {
			t.Fatalf("after the %s: Status = %+v\nproxy log:\n%s", name, status, logOnFailure())
		}
	}

	// A request an API key signs goes to the OpenAI API.
	token, _ := os.ReadFile(TokenPath(filepath.Join(home, "state")))
	signed, _ := http.NewRequest(http.MethodGet, BaseURL(status.Port, strings.TrimSpace(string(token)))+"/models", nil)
	signed.Header.Set("Authorization", "Bearer sk-not-a-real-key")
	response, err := http.DefaultClient.Do(signed)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	mu.Lock()
	seen, forwarded := strings.Join(forwarded, ", "), nil
	mu.Unlock()
	if response.StatusCode != http.StatusOK || seen != "GET /v1/models (signed)" {
		t.Fatalf("an API key's request through the job = %d; upstream saw %q", response.StatusCode, seen)
	}
	// Each proxy run says where the route stands at its first request.
	if !strings.Contains(logOnFailure(), "Codex route held by a daemon\n") {
		t.Fatalf("proxy log:\n%s", logOnFailure())
	}

	// The daemon stopped and the grace ran out: the first request takes the
	// route away, and goes through unchanged.
	st = router.loadState()
	st.Holder = &holder{PID: os.Getpid(), Started: time.Unix(1, 0), Until: time.Now().Add(-time.Second)}
	if err := router.saveState(st); err != nil {
		t.Fatal(err)
	}
	response, err = http.Get(BaseURL(status.Port, strings.TrimSpace(string(token))) + "/models")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	mu.Lock()
	seen = strings.Join(forwarded, ", ")
	mu.Unlock()
	if response.StatusCode != http.StatusOK || seen != "GET /backend-api/codex/models" {
		t.Fatalf("request through the job = %d; upstream saw %q", response.StatusCode, seen)
	}
	if config, _ := os.ReadFile(filepath.Join(home, ".codex", "config.toml")); string(config) != original {
		t.Fatalf("config once no daemon held the route:\n%s\nproxy log:\n%s", config, logOnFailure())
	}
	if !strings.Contains(logOnFailure(), "Codex route not held by a daemon: taken away") {
		t.Fatalf("proxy log:\n%s", logOnFailure())
	}

	if done, err := router.Drain(ctx); err != nil || !done {
		t.Fatalf("Drain = %v, %v", done, err)
	}
	// launchd may finish taking a job away just after bootout returns.
	drained, lingered := time.Now(), false
	for exec.Command("/bin/launchctl", "print", domain).Run() == nil {
		if time.Since(drained) > 5*time.Second {
			t.Fatalf("the job is still loaded 5 s after the drain; launchctl ran:\n%s", ran())
		}
		lingered = true
		time.Sleep(50 * time.Millisecond)
	}
	if lingered {
		t.Logf("the job went %s after the drain; launchctl ran:\n%s", time.Since(drained).Round(time.Millisecond), ran())
	}
	if _, err := os.Stat(BinaryPath(filepath.Join(home, "state"))); !os.IsNotExist(err) {
		t.Fatalf("the job's binary outlived it: %v", err)
	}
}
