package codexroute

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/codexmanaged"
)

const testPort = 49321

// fakeLaunchd stands in for launchctl: it remembers whether the job is
// loaded and every command. After a bootout, it still holds the job for
// linger prints, as launchd may, and refuses a bootstrap meanwhile.
type fakeLaunchd struct {
	mu       sync.Mutex
	loaded   bool
	linger   int
	held     int
	commands []string
}

func (l *fakeLaunchd) run(_ context.Context, args ...string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.commands = append(l.commands, args[0])
	switch args[0] {
	case "print":
		if l.held > 0 {
			l.held--
			return nil
		}
		if !l.loaded {
			return errors.New("could not find service")
		}
	case "bootstrap":
		if l.loaded || l.held > 0 {
			return errors.New("bootstrap failed: 5: input/output error")
		}
		l.loaded = true
	case "bootout":
		l.loaded, l.held = false, l.linger
	}
	return nil
}

func (l *fakeLaunchd) ran(command string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, c := range l.commands {
		if c == command {
			n++
		}
	}
	return n
}

// fakeProcesses stands in for the process table: when each running process
// started.
type fakeProcesses struct {
	mu      sync.Mutex
	started map[int]time.Time
}

func (p *fakeProcesses) lookup(pid int) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	started, ok := p.started[pid]
	return started, ok
}

// run starts another process as pid, as when a daemon restarts and gets a
// pid an earlier one had.
func (p *fakeProcesses) run(pid int, started time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started[pid] = started
}

func (p *fakeProcesses) stop(pid int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.started, pid)
}

type testRouter struct {
	*Router
	home    string
	launchd *fakeLaunchd
	healthy *bool
	codex   *int
	// binary is where the daemon's kontext binary is, and processes the
	// processes running, the test's own as the daemon among them.
	binary    string
	processes *fakeProcesses
	// clock shifts the daemon's time.
	clock *time.Duration
}

const build2 = "kontext build 2\n"

func newTestRouter(t *testing.T) testRouter {
	t.Helper()
	home := t.TempDir()
	r := testRouter{home: home, launchd: &fakeLaunchd{}, healthy: new(bool), codex: new(int), clock: new(time.Duration),
		binary:    filepath.Join(home, "opt", "homebrew", "bin", "kontext"),
		processes: &fakeProcesses{started: map[int]time.Time{os.Getpid(): time.Now().Add(-time.Hour)}}}
	*r.healthy = true
	writeFile(t, r.binary, build2, 0o755)
	writeFile(t, filepath.Join(home, ".codex", "auth.json"), authFor("plus"), 0o600)
	r.Router = r.daemon(t)
	return r
}

// daemon is the router of a daemon started now from r.binary.
func (r testRouter) daemon(t *testing.T) *Router {
	t.Helper()
	binary, err := os.Open(r.binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { binary.Close() })
	return New(Options{
		Home:      r.home,
		Binary:    binary,
		StateDir:  filepath.Join(r.home, "Library", "Application Support", "Kontext", "managed-observe", "codex-proxy"),
		Socket:    "/tmp/kontext-managed-observe-501/kontext.sock",
		GOOS:      "darwin",
		Launchctl: r.launchd.run,
		Health: func(context.Context, int, string) error {
			if !*r.healthy {
				return errors.New("connection refused")
			}
			return nil
		},
		CodexSince:     func(time.Time) (int, error) { return *r.codex, nil },
		ProcessStarted: r.processes.lookup,
		FreePort:       func() (int, error) { return testPort, nil },
		Now:            func() time.Time { return time.Now().Add(*r.clock) },
	})
}

// job is the router the proxy job builds from its flags, asking after
// later.
func (r testRouter) job(later time.Duration) *Router {
	return New(Options{Home: r.home, StateDir: r.opts.StateDir, GOOS: "darwin", ProcessStarted: r.processes.lookup,
		Now: func() time.Time { return time.Now().Add(later) }})
}

// replace puts content at path as a new file, as an update or a downgrade
// does.
func replace(t *testing.T, path, content string) {
	t.Helper()
	writeFile(t, path+".new", content, 0o755)
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
}

func authFor(plan string) string {
	segment := func(value any) string {
		data, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	idToken := segment(map[string]string{"alg": "none"}) + "." +
		segment(map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_plan_type": plan}}) + ".sig"
	data, _ := json.Marshal(map[string]any{"auth_mode": "chatgpt", "tokens": map[string]string{"id_token": idToken, "access_token": "secret"}})
	return string(data)
}

func writeFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

const original = "model = \"gpt-6.1-sol\"\n\n[features]\nhooks = true\n"

func TestEnableRoutesCodexOnlyOnceTheProxyAnswers(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o644)

	*r.healthy = false
	if _, err := r.Enable(context.Background()); err == nil {
		t.Fatal("Enable routed Codex to a port the proxy does not answer on")
	}
	if readFile(t, configPath) != original || r.launchd.loaded {
		t.Fatal("a failed health check left the config changed or the job loaded")
	}

	*r.healthy = true
	status, err := r.Enable(context.Background())
	if err != nil || !status.Routed || status.Port != testPort {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	token := strings.TrimSpace(readFile(t, TokenPath(r.opts.StateDir)))
	routed := readFile(t, configPath)
	if codexmanaged.Route(routed) != BaseURL(testPort, token) || !strings.HasSuffix(routed, original) {
		t.Fatalf("config:\n%s", routed)
	}
	// The file holds the token now, so only its owner may read it.
	if info, err := os.Stat(configPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("routed config mode = %v, %v", info.Mode().Perm(), err)
	}
	if info, err := os.Stat(TokenPath(r.opts.StateDir)); err != nil || info.Mode().Perm() != 0o600 || len(token) != 34 {
		t.Fatalf("token file: %v, %v (%d chars)", info, err, len(token))
	}
	plist := readFile(t, filepath.Join(r.home, "Library", "LaunchAgents", Label+".plist"))
	for _, want := range []string{"<string>" + Label + "</string>", "<string>" + BinaryPath(r.opts.StateDir) + "</string>",
		"<string>codex-proxy</string>", "<string>--stdin-socket</string>", "<string>--home</string>\n\t\t<string>" + r.home + "</string>",
		"<string>49321</string>", "<key>Wait</key>\n\t\t<true/>", "<string>127.0.0.1</string>", "<integer>1</integer>"} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist lacks %q:\n%s", want, plist)
		}
	}
	if strings.Contains(plist, token) || strings.Contains(plist, r.binary) || strings.Contains(plist, "--upstream") {
		t.Fatal("the plist carries the token, runs the daemon's binary, or forwards elsewhere")
	}

	// Enabling again changes nothing and reloads nothing.
	bootstraps := r.launchd.ran("bootstrap")
	if _, err := r.Enable(context.Background()); err != nil || readFile(t, configPath) != routed || r.launchd.ran("bootstrap") != bootstraps {
		t.Fatalf("a second Enable changed something: %v", err)
	}
}

func TestEnableLeavesTheirOwnRouteAlone(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The person switches Codex to another provider: Kontext's line goes.
	routed := readFile(t, configPath)
	theirs := strings.Replace(routed, "model = ", "model_provider = \"ollama\"\nmodel = ", 1)
	writeFile(t, configPath, theirs, 0o600)
	status, err := r.Enable(context.Background())
	if err != nil || status.Routed || status.Skipped != "model_provider is ollama" {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	if got := readFile(t, configPath); codexmanaged.Route(got) != "" || !strings.Contains(got, "model_provider = \"ollama\"") {
		t.Fatalf("config:\n%s", got)
	}
}

// However Codex is signed in, it is routed: the proxy sends each request
// where its credentials belong. The router never reads them.
func TestEnableRoutesEveryLogin(t *testing.T) {
	logins := map[string]string{
		"API key":       `{"auth_mode":"apikey","OPENAI_API_KEY":"sk-test"}`,
		"older API key": `{"OPENAI_API_KEY":"sk-test"}`,
		// The keyring holds the login, or the ChatGPT app passes its tokens.
		"no auth.json": "",
	}
	for _, plan := range []string{"free", "plus", "pro", "business", "enterprise", "edu"} {
		logins["ChatGPT "+plan] = authFor(plan)
	}
	for name, auth := range logins {
		t.Run(name, func(t *testing.T) {
			r := newTestRouter(t)
			authPath := filepath.Join(r.home, ".codex", "auth.json")
			if auth == "" {
				_ = os.Remove(authPath)
			} else {
				writeFile(t, authPath, auth, 0o600)
			}
			if err := os.Chmod(authPath, 0); auth != "" && err != nil {
				t.Fatal(err)
			}
			if status, err := r.Enable(context.Background()); err != nil || !status.Routed {
				t.Fatalf("Enable = %+v, %v", status, err)
			}
		})
	}
}

func TestSwitchOffChangesNothingInCodex(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	before, _ := os.Stat(configPath)
	if err := r.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if done, err := r.Drain(context.Background()); err != nil || !done {
		t.Fatalf("Drain = %v, %v", done, err)
	}
	if err := r.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(configPath)
	if readFile(t, configPath) != original || !after.ModTime().Equal(before.ModTime()) {
		t.Fatal("the switch being off changed config.toml")
	}
	if _, err := os.Stat(r.opts.StateDir); !os.IsNotExist(err) {
		t.Fatalf("state was written: %v", err)
	}
	if len(r.launchd.commands) != 0 {
		t.Fatalf("launchctl ran: %v", r.launchd.commands)
	}
}

func TestDisableKeepsTheJobUntilCodexDrains(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if readFile(t, configPath) != original {
		t.Fatalf("config after Disable:\n%s", readFile(t, configPath))
	}
	*r.codex = 1
	if done, err := r.Drain(context.Background()); err != nil || done || !r.launchd.loaded {
		t.Fatalf("Drain unloaded the job while Codex may still call it: %v, %v", done, err)
	}
	if status := r.Status(context.Background()); status.Routed || !status.Loaded || status.Draining != 1 {
		t.Fatalf("Status = %+v", status)
	}
	*r.codex = 0
	if done, err := r.Drain(context.Background()); err != nil || !done || r.launchd.loaded {
		t.Fatalf("Drain = %v, %v", done, err)
	}
	if _, err := os.Stat(filepath.Join(r.home, "Library", "LaunchAgents", Label+".plist")); !os.IsNotExist(err) {
		t.Fatalf("plist kept: %v", err)
	}
	// Turning the switch on again reuses the port and token.
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed || status.Port != testPort {
		t.Fatalf("Enable again = %+v, %v", status, err)
	}
}

func TestRemoveTakesTheLineFirstAndEverythingAfter(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	*r.codex = 2
	left, err := r.Remove(context.Background(), 0)
	if err != nil || left != 2 {
		t.Fatalf("Remove = %d, %v", left, err)
	}
	if readFile(t, configPath) != original || r.launchd.loaded {
		t.Fatal("Remove left the line or the job")
	}
	for _, path := range []string{r.opts.StateDir, filepath.Join(r.home, "Library", "LaunchAgents", Label+".plist")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s kept: %v", path, err)
		}
	}
}

func TestACreatedConfigGoesWithTheLine(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(configPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("created config: %v, %v", info, err)
	}
	if err := r.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Fatalf("the config Kontext created was kept: %v", err)
	}
}

func TestOffMacOSNothingChanges(t *testing.T) {
	r := newTestRouter(t)
	r.opts.GOOS = "linux"
	status, err := r.Enable(context.Background())
	if err != nil || status.Routed || status.Skipped == "" || len(r.launchd.commands) != 0 {
		t.Fatalf("Enable = %+v, %v, launchctl %v", status, err, r.launchd.commands)
	}
	if _, err := os.Stat(filepath.Join(r.home, ".codex", "config.toml")); !os.IsNotExist(err) {
		t.Fatalf("config.toml written: %v", err)
	}
}

func TestARoutedJobSurvivesMissedHealthChecks(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)
	*r.healthy = false
	for miss := 1; miss < maxHealthFailures; miss++ {
		if _, err := r.Enable(context.Background()); err == nil {
			t.Fatal("a missed health check passed")
		}
		// Codex reads the port: the job and the route stay as they are.
		if readFile(t, configPath) != routed || !r.launchd.loaded || r.loadState().Port != testPort {
			t.Fatalf("miss %d changed the route or unloaded the job", miss)
		}
	}
	if _, err := r.Enable(context.Background()); err == nil {
		t.Fatal("the last missed health check passed")
	}
	if readFile(t, configPath) != original {
		t.Fatalf("after %d misses Codex is still routed:\n%s", maxHealthFailures, readFile(t, configPath))
	}
	if st := r.loadState(); st.UnroutedAt.IsZero() || !r.launchd.loaded {
		t.Fatalf("the job should drain, not go at once: %+v, loaded %v", st, r.launchd.loaded)
	}
}

func TestEnableKeepsThePortAndTokenCodexReads(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	token := "kx" + strings.Repeat("ab", 16)
	line := "openai_base_url = \"" + BaseURL(50001, token) + "\" " + codexmanaged.RouteMarker + "\n"
	writeFile(t, configPath, line+original, 0o600)
	if err := r.saveState(state{Port: testPort}); err != nil {
		t.Fatal(err)
	}
	status, err := r.Enable(context.Background())
	if err != nil || status.Port != 50001 {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	if readFile(t, configPath) != line+original || strings.TrimSpace(readFile(t, TokenPath(r.opts.StateDir))) != token {
		t.Fatal("Enable moved the route Codex reads")
	}
	if !strings.Contains(readFile(t, filepath.Join(r.home, "Library", "LaunchAgents", Label+".plist")), "<string>50001</string>") {
		t.Fatal("the job does not hold the port Codex reads")
	}
}

func TestASymlinkedConfigStaysALink(t *testing.T) {
	r := newTestRouter(t)
	target := filepath.Join(r.home, "dotfiles", "codex.toml")
	writeFile(t, target, original, 0o600)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	if err := os.Symlink(target, configPath); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(configPath); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("config.toml is no longer a link: %v, %v", info, err)
	}
	if codexmanaged.Route(readFile(t, target)) == "" {
		t.Fatal("the linked file was not routed")
	}
	if err := r.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if readFile(t, target) != original {
		t.Fatalf("the linked file after Disable:\n%s", readFile(t, target))
	}
}

func TestARouteInAConfigThatNoLongerParsesStillGoes(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The person adds a gateway of their own at the top: two openai_base_urls,
	// which Codex cannot load.
	theirs := "openai_base_url = \"https://gateway.example/v1\"\n"
	routedLine, rest, _ := strings.Cut(readFile(t, configPath), "\n")
	writeFile(t, configPath, routedLine+"\n"+theirs+rest, 0o600)
	if status, err := r.Enable(context.Background()); err != nil || status.Routed || status.Skipped == "" {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	if got := readFile(t, configPath); got != theirs+original {
		t.Fatalf("config:\n%s", got)
	}
}

func TestTheConfigIsPrivateWhileItHoldsTheToken(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o644)
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(configPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("routed config mode = %v", info.Mode().Perm())
	}
	if err := r.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(configPath); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode after Disable = %v", info.Mode().Perm())
	}
}

func TestHealthErrorsLeaveTheTokenOut(t *testing.T) {
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	token := "kx" + strings.Repeat("cd", 16)
	err = health(context.Background(), port, token)
	if err == nil || strings.Contains(err.Error(), token) {
		t.Fatalf("health error = %v", err)
	}
}

// The job runs a copy of the daemon's binary that it keeps for itself: what
// later happens to the file the daemon started from never reaches the job.
func TestTheJobRunsItsOwnCopyOfTheDaemonsBinary(t *testing.T) {
	r := newTestRouter(t)
	writeFile(t, filepath.Join(r.home, ".codex", "config.toml"), original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	copied := BinaryPath(r.opts.StateDir)
	before, err := os.Stat(copied)
	if err != nil || before.Mode().Perm() != 0o700 || readFile(t, copied) != build2 {
		t.Fatalf("the job's copy: %v, %v", before, err)
	}
	elsewhere := filepath.Join(r.home, "elsewhere")
	writeFile(t, elsewhere, "Latest main, built without the proxy\n", 0o755)
	for name, change := range map[string]func(){
		// A downgrade or a rollback puts a build without the proxy at the
		// path.
		"downgrade": func() { replace(t, r.binary, "kontext build 1, without the proxy\n") },
		// Homebrew deletes the old version after an upgrade.
		"cleanup": func() { _ = os.Remove(r.binary) },
		// KontextManagement points its symlink at another build.
		"symlink": func() { _ = os.Remove(r.binary); _ = os.Symlink(elsewhere, r.binary) },
	} {
		change()
		if _, err := r.Enable(context.Background()); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		after, err := os.Stat(copied)
		if err != nil || !os.SameFile(before, after) || readFile(t, copied) != build2 {
			t.Fatalf("%s reached the job's copy: %v", name, err)
		}
	}
}

// The copy is of the binary the daemon started from, even when an update or
// a downgrade put another build at its path before it first routed Codex.
func TestTheCopyIsOfTheBinaryTheDaemonStartedFrom(t *testing.T) {
	r := newTestRouter(t)
	writeFile(t, filepath.Join(r.home, ".codex", "config.toml"), original, 0o600)
	replace(t, r.binary, "kontext build 1, without the proxy\n")
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, BinaryPath(r.opts.StateDir)); got != build2 {
		t.Fatalf("the job's copy is %q", got)
	}
}

// A daemon started from another build gives the job a copy of that build, as
// a new file, since the kernel keeps what it checked of a binary with the
// file; one started from the same build leaves the copy as it is, and a copy
// that went missing is made again.
func TestADaemonOfAnotherBuildReplacesTheCopy(t *testing.T) {
	r := newTestRouter(t)
	writeFile(t, filepath.Join(r.home, ".codex", "config.toml"), original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	copied := BinaryPath(r.opts.StateDir)
	first, _ := os.Stat(copied)
	if _, err := r.daemon(t).Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if same, _ := os.Stat(copied); !os.SameFile(first, same) {
		t.Fatal("a daemon of the same build made the copy again")
	}
	replace(t, r.binary, "kontext build 3\n")
	build3 := r.daemon(t)
	if _, err := build3.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	updated, _ := os.Stat(copied)
	if os.SameFile(first, updated) || readFile(t, copied) != "kontext build 3\n" {
		t.Fatal("an update did not give the job a new copy of its build")
	}
	if err := os.Remove(copied); err != nil {
		t.Fatal(err)
	}
	if _, err := build3.Enable(context.Background()); err != nil || readFile(t, copied) != "kontext build 3\n" {
		t.Fatalf("a missing copy was not made again: %v", err)
	}
}

// olderPlist is the plist builds from before the job's own copy and the
// lease wrote: the job ran the daemon's binary where it is installed, and
// had no --home.
func olderPlist(j job, installed string) string {
	j.binary = installed
	return strings.Replace(renderPlist(j), "\t\t<string>--home</string>\n\t\t<string>"+xmlEscape(j.home)+"</string>\n", "", 1)
}

// A daemon of this build starts where an older build left Codex routed: the
// job loaded from that build's plist, and route.json naming neither a holder
// nor a copy. Enabling keeps the line, so the Codex processes that read it
// keep their port and token, and reloads the job once, from its own copy,
// though launchd holds the old job a moment after bootout.
func TestADaemonTakesOverTheJobOfAnOlderBuild(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed, plist := readFile(t, configPath), readFile(t, r.plistPath())
	older := job{label: Label, port: testPort, home: r.home, stateDir: r.opts.StateDir, socket: r.opts.Socket, logPath: r.logPath()}
	writeFile(t, r.plistPath(), olderPlist(older, r.binary), 0o644)
	st := r.loadState()
	st.Holder, st.Binary = nil, ""
	if err := r.saveState(st); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Dir(BinaryPath(r.opts.StateDir))); err != nil {
		t.Fatal(err)
	}
	r.launchd.linger = 3
	bootouts, bootstraps := r.launchd.ran("bootout"), r.launchd.ran("bootstrap")

	daemon := r.daemon(t)
	status, err := daemon.Enable(context.Background())
	if err != nil || !status.Routed || status.Port != testPort {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	if readFile(t, configPath) != routed {
		t.Fatalf("the line changed:\n%s", readFile(t, configPath))
	}
	if readFile(t, r.plistPath()) != plist || readFile(t, BinaryPath(r.opts.StateDir)) != build2 {
		t.Fatalf("the job does not run its own copy:\n%s", readFile(t, r.plistPath()))
	}
	if r.launchd.ran("bootout") != bootouts+1 || r.launchd.ran("bootstrap") != bootstraps+1 || !r.launchd.loaded {
		t.Fatalf("launchctl ran %v", r.launchd.commands)
	}
	if !daemon.Status(context.Background()).Held {
		t.Fatal("the daemon does not hold the route it took over")
	}
	if _, err := daemon.Enable(context.Background()); err != nil || r.launchd.ran("bootstrap") != bootstraps+1 {
		t.Fatalf("a second Enable reloaded the job again: %v", err)
	}
}

// The job's binary goes with the job.
func TestTheCopyGoesWithTheJob(t *testing.T) {
	r := newTestRouter(t)
	writeFile(t, filepath.Join(r.home, ".codex", "config.toml"), original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if done, err := r.Drain(context.Background()); err != nil || !done {
		t.Fatalf("Drain = %v, %v", done, err)
	}
	if _, err := os.Stat(filepath.Dir(BinaryPath(r.opts.StateDir))); !os.IsNotExist(err) {
		t.Fatalf("the job's binary outlived it: %v", err)
	}
}

// While the daemon that routed Codex runs, or it stopped less than the grace
// ago, the proxy job keeps the route. After that, as when a build without
// the proxy replaced the daemon and never renews, the job takes the line
// away, keeping the job itself for the Codex processes that read it.
func TestTheRouteGoesOnceNoDaemonHoldsIt(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o644)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)
	// A daemon that slept through the night still holds it.
	if held, err := r.job(24 * time.Hour).Held(context.Background()); err != nil || !held || readFile(t, configPath) != routed {
		t.Fatalf("Held with the daemon running = %v, %v", held, err)
	}
	r.processes.stop(os.Getpid())
	if held, err := r.job(leaseGrace - time.Minute).Held(context.Background()); err != nil || !held || readFile(t, configPath) != routed {
		t.Fatalf("Held within the grace = %v, %v", held, err)
	}
	if status := r.Status(context.Background()); !status.Routed || !status.Held {
		t.Fatalf("Status within the grace = %+v", status)
	}
	if held, err := r.job(leaseGrace + time.Minute).Held(context.Background()); err != nil || held {
		t.Fatalf("Held after the grace = %v, %v", held, err)
	}
	if info, _ := os.Stat(configPath); readFile(t, configPath) != original || info.Mode().Perm() != 0o644 {
		t.Fatalf("config after the route went (%v):\n%s", info.Mode().Perm(), readFile(t, configPath))
	}
	if held, err := r.job(leaseGrace + time.Hour).Held(context.Background()); err != nil || held {
		t.Fatalf("Held once the route went = %v, %v", held, err)
	}
	*r.codex = 1
	if done, err := r.Drain(context.Background()); err != nil || done || !r.launchd.loaded {
		t.Fatalf("Drain unloaded the job while Codex may still call it: %v, %v", done, err)
	}
}

// A daemon that restarts holds the route again within the grace, though
// another process may now have the pid it had.
func TestARestartedDaemonHoldsTheRouteAgain(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)
	r.processes.run(os.Getpid(), time.Now())
	*r.clock = leaseGrace + time.Minute
	if status := r.Status(context.Background()); status.Held {
		t.Fatal("a process that took the stopped daemon's pid holds its route")
	}
	*r.clock = 0
	if held, err := r.job(time.Minute).Held(context.Background()); err != nil || !held {
		t.Fatalf("Held within the grace = %v, %v", held, err)
	}
	if err := r.daemon(t).Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if held, err := r.job(leaseGrace + time.Hour).Held(context.Background()); err != nil || !held || readFile(t, configPath) != routed {
		t.Fatalf("Held after the restart = %v, %v", held, err)
	}
}

// The daemon renews its hold while Codex is routed, and holds nothing once
// the switch takes the route away.
func TestTheDaemonHoldsOnlyARoute(t *testing.T) {
	r := newTestRouter(t)
	writeFile(t, filepath.Join(r.home, ".codex", "config.toml"), original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := r.loadState().Holder
	*r.clock = 5 * time.Minute
	if err := r.Renew(context.Background()); err != nil {
		t.Fatal(err)
	}
	if renewed := r.loadState().Holder; renewed == nil || renewed.Until.Sub(first.Until) < 5*time.Minute {
		t.Fatalf("Renew left the hold at %+v", renewed)
	}
	if err := r.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Renew(context.Background()); err != nil || r.loadState().Holder != nil {
		t.Fatalf("a daemon holds a route it took away: %v", err)
	}
	if held, err := r.job(0).Held(context.Background()); err != nil || held {
		t.Fatalf("Held = %v, %v without a route", held, err)
	}
}

// While a daemon changes the route, the proxy job leaves it to it.
func TestTheJobLeavesTheRouteToADaemonChangingIt(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)
	r.processes.stop(os.Getpid())
	unlock, locked, err := lockFile(r.lockPath(), true)
	if err != nil || !locked {
		t.Fatal(err)
	}
	if held, err := r.job(leaseGrace + time.Hour).Held(context.Background()); err != nil || !held || readFile(t, configPath) != routed {
		t.Fatalf("Held during a change = %v, %v", held, err)
	}
	unlock()
	if held, err := r.job(leaseGrace + time.Hour).Held(context.Background()); err != nil || held || readFile(t, configPath) != original {
		t.Fatalf("Held after the change = %v, %v", held, err)
	}
}

// A route the job took away comes back with the next daemon, on the port and
// token the Codex processes still calling the job read.
func TestARouteTakenAwayComesBackWithTheDaemon(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)
	r.processes.stop(os.Getpid())
	if held, err := r.job(leaseGrace + time.Minute).Held(context.Background()); err != nil || held {
		t.Fatalf("Held = %v, %v", held, err)
	}
	r.processes.run(os.Getpid(), time.Now())
	if status, err := r.daemon(t).Enable(context.Background()); err != nil || !status.Routed || readFile(t, configPath) != routed {
		t.Fatalf("Enable = %+v, %v; config:\n%s", status, err, readFile(t, configPath))
	}
}
