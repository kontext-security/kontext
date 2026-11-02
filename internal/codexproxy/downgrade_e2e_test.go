package codexproxy_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/codexproxy"
	"github.com/kontext-security/kontext/internal/codexroute"
)

// TestCodexAfterDowngrade routes a real Codex binary through the proxy's real
// launchd job, then downgrades the daemon's binary to a build without the
// proxy, which never renews the route. Codex's turns still finish, through
// the job's own copy of the binary, and once the route's lease runs out the
// job takes the route away. A mock backend answers, and a Seatbelt profile
// refuses every connection off the machine. Opt in with
// KONTEXT_CODEX_E2E_BIN=/path/to/codex and KONTEXT_LAUNCHD_E2E_BIN=/path/to/kontext;
// KONTEXT_DOWNGRADE_E2E_BIN names the older kontext build, a script that fails
// as one does by default (see scripts/codex-proxy-e2e.sh).
func TestCodexAfterDowngrade(t *testing.T) {
	codex, built := os.Getenv("KONTEXT_CODEX_E2E_BIN"), os.Getenv("KONTEXT_LAUNCHD_E2E_BIN")
	if codex == "" || built == "" {
		t.Skip("set KONTEXT_CODEX_E2E_BIN and KONTEXT_LAUNCHD_E2E_BIN to run")
	}
	if runtime.GOOS != "darwin" {
		t.Skip("uses launchd and sandbox-exec; macOS only")
	}
	backend := &codexproxy.E2EBackend{}
	models, chatgpt := httptest.NewServer(backend), httptest.NewServer(backend)
	defer models.Close()
	defer chatgpt.Close()

	root, err := os.MkdirTemp("/tmp", "kx-downgrade-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	home, workspace := filepath.Join(root, "home"), filepath.Join(root, "workspace")
	codexHome := filepath.Join(home, ".codex")
	for _, dir := range []string{codexHome, workspace, filepath.Join(root, "install")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	original := "model = \"gpt-6.1-sol\"\ncli_auth_credentials_store = \"file\"\nweb_search = \"disabled\"\n"
	configPath := filepath.Join(codexHome, "config.toml")
	for path, content := range map[string]string{filepath.Join(codexHome, "auth.json"): codexproxy.E2ELogin(), configPath: original} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	installed := filepath.Join(root, "install", "kontext")
	install := func(from []byte) {
		t.Helper()
		if err := os.WriteFile(installed+".new", from, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(installed+".new", installed); err != nil {
			t.Fatal(err)
		}
	}
	current, err := os.ReadFile(built)
	if err != nil {
		t.Fatal(err)
	}
	install(current)
	binary, err := os.Open(installed)
	if err != nil {
		t.Fatal(err)
	}
	defer binary.Close()

	const grace = 15 * time.Second
	stateDir := filepath.Join(root, "state")
	router := codexroute.New(codexroute.Options{Home: home, Binary: binary, StateDir: stateDir, Socket: filepath.Join(root, "no-daemon.sock"),
		Label: codexroute.Label + ".e2e-" + strconv.Itoa(os.Getpid()), Upstream: models.URL + "/backend-api/codex",
		APIUpstream: models.URL + "/v1", LeaseGrace: grace,
		// The daemon is gone by the time Codex runs: the start time no process
		// has stands for it in the lease.
		ProcessStarted: func(int) (time.Time, bool) { return time.Unix(1, 0), true },
		CodexSince:     func(time.Time) (int, error) { return 0, nil }})
	ctx := context.Background()
	defer func() {
		if _, err := router.Remove(ctx, 0); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	}()
	proxyLog := func() string {
		log, _ := os.ReadFile(filepath.Join(home, "Library", "Logs", "Kontext", "codex-proxy.log"))
		return string(log)
	}
	routedAt := time.Now()
	if status, err := router.Enable(ctx); err != nil || !status.Routed {
		t.Fatalf("Enable = %+v, %v\nproxy log:\n%s", status, err, proxyLog())
	}
	routed, _ := os.ReadFile(configPath)

	// The downgrade: an older build replaces the daemon's binary.
	old := []byte("#!/bin/sh\necho 'Error: unknown command \"codex-proxy\" for \"kontext\"' >&2\nexit 1\n")
	if path := os.Getenv("KONTEXT_DOWNGRADE_E2E_BIN"); path != "" {
		if old, err = os.ReadFile(path); err != nil {
			t.Fatal(err)
		}
	}
	install(old)
	if out, err := exec.Command(installed, "codex-proxy", "--help").CombinedOutput(); err == nil {
		t.Fatalf("the older build runs the proxy:\n%s", out)
	}

	profile := filepath.Join(root, "sandbox.sb")
	sandbox := "(version 1)\n(allow default)\n(deny network-outbound)\n(allow network-outbound (remote ip \"localhost:*\"))\n(allow network-outbound (remote unix-socket))\n"
	if err := os.WriteFile(profile, []byte(sandbox), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(prompt string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sandbox-exec", "-f", profile, codex, "-c", "features.code_mode_host=true",
			"-c", "chatgpt_base_url="+strconv.Quote(chatgpt.URL+"/backend-api/"), "exec",
			"--skip-git-repo-check", "--json", "--dangerously-bypass-approvals-and-sandbox", "-")
		cmd.Dir, cmd.Stdin = workspace, strings.NewReader(prompt)
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + home, "CODEX_HOME=" + codexHome, "CI=1", "NO_COLOR=1", "LANG=en_US.UTF-8"}
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("codex exec: %v\nevents:\n%s\nstderr:\n%s\nproxy log:\n%s", err, stdout.String(), stderr.String(), proxyLog())
		}
		events := stdout.String()
		if !strings.Contains(events, `"text":"DONE"`) || strings.Contains(events, "Reconnecting") {
			t.Fatalf("the turn did not finish cleanly:\n%s", events)
		}
		return events
	}

	// Within the lease, the route stays, and Codex reaches the backend
	// through the job's copy.
	run("Run the scripts, then reply DONE.")
	if config, _ := os.ReadFile(configPath); !bytes.Equal(config, routed) || codexmanaged.Route(string(config)) == "" {
		t.Fatalf("config within the lease:\n%s", config)
	}
	// The older build never renews it. Once it runs out, the next Codex
	// still finishes its turn, and its first request takes the route away.
	time.Sleep(time.Until(routedAt.Add(grace + time.Second)))
	run("Run them again, then reply DONE.")
	if config, _ := os.ReadFile(configPath); string(config) != original {
		t.Fatalf("config once the lease ran out:\n%s\nproxy log:\n%s", config, proxyLog())
	}
	if !strings.Contains(proxyLog(), "Codex route not held by a daemon: taken away") {
		t.Fatalf("proxy log:\n%s", proxyLog())
	}
	if n := backend.Responses(); n != 6 {
		t.Fatalf("the backend answered %d model requests, want 3 per turn", n)
	}
}
