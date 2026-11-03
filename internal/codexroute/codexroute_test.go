package codexroute

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/codexmanaged"
)

const testPort = 49321

// fakeLaunchd stands in for launchctl: it remembers whether the job is
// loaded and every command. After a bootout, it still holds the job for
// linger prints, as launchd may, and refuses a bootstrap meanwhile; it also
// refuses the first refuse bootstraps.
type fakeLaunchd struct {
	mu       sync.Mutex
	loaded   bool
	linger   int
	held     int
	refuse   int
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
		if l.loaded || l.held > 0 || l.refuse > 0 {
			l.refuse = max(l.refuse-1, 0)
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
	// reaches says whether the job reaches OpenAI, env is the daemon's
	// environment, scutil what macOS's proxy settings print as, and admin
	// what Codex's administrator layers say.
	reaches *bool
	env     map[string]string
	scutil  *scutilAnswer
	admin   *adminAnswer
	codex   *int
	// binary is where the daemon's kontext binary is, and processes the
	// processes running, the test's own as the daemon among them.
	binary    string
	processes *fakeProcesses
	// clock shifts the daemon's time.
	clock *time.Duration
}

// adminAnswer is what Codex's administrator layers say about the route.
type adminAnswer struct {
	blocker codexmanaged.Blocker
	err     error
}

// scutilAnswer is what scutil --proxy prints, or err, and how many times it
// was asked; once asked failAfter times, when that is set, it fails.
type scutilAnswer struct {
	output    string
	err       error
	asked     int
	failAfter int
}

const build2 = "kontext build 2\n"

func newTestRouter(t *testing.T) testRouter {
	t.Helper()
	home := t.TempDir()
	r := testRouter{home: home, launchd: &fakeLaunchd{}, healthy: new(bool), reaches: new(bool), env: map[string]string{},
		scutil: &scutilAnswer{output: noProxies}, admin: &adminAnswer{}, codex: new(int), clock: new(time.Duration),
		binary:    filepath.Join(home, "opt", "homebrew", "bin", "kontext"),
		processes: &fakeProcesses{started: map[int]time.Time{os.Getpid(): time.Now().Add(-time.Hour)}}}
	*r.healthy, *r.reaches = true, true
	writeFile(t, r.binary, build2, 0o755)
	writeFile(t, filepath.Join(home, ".codex", "auth.json"), authFor("plus"), 0o600)
	r.Router = r.daemon(t)
	return r
}

// daemon is the router of a daemon started now from r.binary.
func (r testRouter) daemon(t *testing.T) *Router {
	t.Helper()
	return r.daemonIn(t, filepath.Join(r.home, "Library", "Application Support", "Kontext", "managed-observe", "codex-proxy"))
}

// daemonIn is daemon, keeping the proxy's state in stateDir.
func (r testRouter) daemonIn(t *testing.T, stateDir string) *Router {
	t.Helper()
	binary, err := os.Open(r.binary)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { binary.Close() })
	return New(Options{
		Home:      r.home,
		Binary:    binary,
		StateDir:  stateDir,
		Socket:    "/tmp/kontext-managed-observe-501/kontext.sock",
		GOOS:      "darwin",
		Launchctl: r.launchd.run,
		Health: func(context.Context, int, string) error {
			if !*r.healthy {
				return errors.New("connection refused")
			}
			return nil
		},
		Reach: func(ctx context.Context, _ int, _ string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if !*r.reaches {
				return errors.New("unexpected answer 502")
			}
			return nil
		},
		LookupEnv: func(name string) (string, bool) {
			value, ok := r.env[name]
			return value, ok
		},
		SystemProxies: func(context.Context) (string, error) {
			r.scutil.asked++
			if r.scutil.failAfter > 0 && r.scutil.asked > r.scutil.failAfter {
				return "", errors.New("exit status 1")
			}
			return r.scutil.output, r.scutil.err
		},
		AdminRoute: func(codexHome string) (codexmanaged.Blocker, error) {
			if codexHome != filepath.Join(r.home, ".codex") {
				return codexmanaged.Blocker{}, errors.New("asked about another Codex home: " + codexHome)
			}
			return r.admin.blocker, r.admin.err
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

// hook is the router Codex's session start hook builds, whose health check
// gets answer, and asks is told each time it does.
func (r testRouter) hook(answer error, asks func(ctx context.Context)) *Router {
	return New(Options{Home: r.home, StateDir: r.opts.StateDir, GOOS: "darwin", ProcessStarted: r.processes.lookup,
		Health: func(ctx context.Context, _ int, _ string) error {
			if asks != nil {
				asks(ctx)
			}
			return answer
		}})
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
	// Opened up again while it holds the token, it is kept private again.
	if err := os.Chmod(configPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(configPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("config mode after it was opened up again = %v", info.Mode().Perm())
	}
	if err := r.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(configPath); info.Mode().Perm() != 0o644 {
		t.Fatalf("mode after Disable = %v", info.Mode().Perm())
	}
}

// Codex's config may change while Enable starts the job, by hand or by a hook
// repair: the line goes into the file as it is then, so nothing written
// meanwhile is lost, and a route of the person's own set meanwhile stands.
func TestEnableKeepsWhatChangedInTheConfigMeanwhile(t *testing.T) {
	for name, edit := range map[string]string{
		"an edit":   original + "\n[mcp_servers.docs]\ncommand = \"docs\"\n",
		"own route": "openai_base_url = \"https://gateway.example/v1\"\n" + original,
	} {
		t.Run(name, func(t *testing.T) {
			r := newTestRouter(t)
			configPath := filepath.Join(r.home, ".codex", "config.toml")
			writeFile(t, configPath, original, 0o600)
			r.opts.Health = func(context.Context, int, string) error {
				writeFile(t, configPath, edit, 0o600)
				return nil
			}
			status, err := r.Enable(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			got := readFile(t, configPath)
			if name == "own route" {
				if status.Routed || got != edit {
					t.Fatalf("Enable = %+v; config:\n%s", status, got)
				}
				return
			}
			if !status.Routed || !strings.HasSuffix(got, edit) || codexmanaged.Route(got) == "" {
				t.Fatalf("Enable = %+v; config:\n%s", status, got)
			}
		})
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

// A port nothing calls any more, once the job drained or when the job did not
// load before Codex was routed, is given up: another process may take it, so
// the next route takes a new one.
func TestAPortNothingCallsIsGivenUp(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	next := testPort
	r.opts.FreePort = func() (int, error) { next++; return next, nil }
	ctx := context.Background()
	r.launchd.refuse = 1
	if _, err := r.Enable(ctx); err == nil {
		t.Fatal("Enable routed Codex through a job launchd refused")
	}
	if status, err := r.Enable(ctx); err != nil || status.Port != testPort+2 {
		t.Fatalf("Enable after a refused job = %+v, %v", status, err)
	}
	if err := r.Disable(ctx); err != nil {
		t.Fatal(err)
	}
	if done, err := r.Drain(ctx); err != nil || !done {
		t.Fatalf("Drain = %v, %v", done, err)
	}
	if st := r.loadState(); st.Port != 0 {
		t.Fatalf("a drained job kept port %d", st.Port)
	}
	if status, err := r.Enable(ctx); err != nil || status.Port != testPort+3 || !strings.Contains(codexmanaged.Route(readFile(t, configPath)), ":"+strconv.Itoa(testPort+3)+"/") {
		t.Fatalf("Enable after a drain = %+v, %v", status, err)
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

// refused is what the health check finds where nothing listens.
var refused = &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}

// Codex's session start hook takes away a route nothing answers on, though
// the daemon that holds it still runs, and leaves every other route alone.
func TestASessionStartTakesAwayARouteNothingAnswers(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o644)

	// Never routed: the hook asks the proxy nothing.
	asked := 0
	count := func(context.Context) { asked++ }
	if unrouted, err := r.hook(refused, count).UnrouteUnanswered(context.Background()); err != nil || unrouted || asked != 0 {
		t.Fatalf("UnrouteUnanswered without a route = %v, %v (asked %d times)", unrouted, err, asked)
	}

	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)
	// A proxy that answers, or answers wrongly, or hangs up, is the daemon's
	// to judge.
	for _, answer := range []error{nil, errors.New("unexpected answer 404"), io.EOF} {
		if unrouted, err := r.hook(answer, nil).UnrouteUnanswered(context.Background()); err != nil || unrouted || readFile(t, configPath) != routed {
			t.Fatalf("UnrouteUnanswered with %v = %v, %v", answer, unrouted, err)
		}
	}
	// While a daemon changes the route, the hook leaves it to it.
	unlock, locked, err := lockFile(r.lockPath(), true)
	if err != nil || !locked {
		t.Fatal(err)
	}
	if unrouted, err := r.hook(refused, nil).UnrouteUnanswered(context.Background()); err != nil || unrouted || readFile(t, configPath) != routed {
		t.Fatalf("UnrouteUnanswered during a change = %v, %v", unrouted, err)
	}
	unlock()

	var deadline time.Time
	unrouted, err := r.hook(refused, func(ctx context.Context) { deadline, _ = ctx.Deadline() }).UnrouteUnanswered(context.Background())
	if err != nil || !unrouted {
		t.Fatalf("UnrouteUnanswered with nothing listening = %v, %v", unrouted, err)
	}
	if deadline.IsZero() || time.Until(deadline) > answerWait {
		t.Fatalf("the hook waited for the proxy until %v", deadline)
	}
	// The line goes as the job takes it away: the config's mode comes back,
	// and the job stays for the Codex processes that read the line.
	if info, _ := os.Stat(configPath); readFile(t, configPath) != original || info.Mode().Perm() != 0o644 {
		t.Fatalf("config after the hook (%v):\n%s", info.Mode().Perm(), readFile(t, configPath))
	}
	if st := r.loadState(); st.Holder != nil || st.UnroutedAt.IsZero() || !r.launchd.loaded {
		t.Fatalf("state after the hook: %+v, job loaded %v", st, r.launchd.loaded)
	}
	// It never adds the line back.
	if unrouted, err := r.hook(nil, nil).UnrouteUnanswered(context.Background()); err != nil || unrouted || readFile(t, configPath) != original {
		t.Fatalf("UnrouteUnanswered once the line went = %v, %v", unrouted, err)
	}
	// Nor does it ever answer for a route off macOS.
	offMac := New(Options{Home: r.home, StateDir: r.opts.StateDir, GOOS: "linux", Health: func(context.Context, int, string) error { return refused }})
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if unrouted, err := offMac.UnrouteUnanswered(context.Background()); err != nil || unrouted || readFile(t, configPath) != routed {
		t.Fatalf("UnrouteUnanswered off macOS = %v, %v", unrouted, err)
	}
}

// A proxy that does not answer in time counts as none; a daemon that routed
// Codex elsewhere meanwhile keeps its route.
func TestASessionStartLeavesANewRouteAlone(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	token := strings.TrimSpace(readFile(t, TokenPath(r.opts.StateDir)))
	elsewhere, err := codexmanaged.AddRoute(original, BaseURL(testPort+1, token))
	if err != nil {
		t.Fatal(err)
	}
	hook := r.hook(context.DeadlineExceeded, func(context.Context) { writeFile(t, configPath, elsewhere, 0o600) })
	if unrouted, err := hook.UnrouteUnanswered(context.Background()); err != nil || unrouted || readFile(t, configPath) != elsewhere {
		t.Fatalf("UnrouteUnanswered over a new route = %v, %v; config:\n%s", unrouted, err, readFile(t, configPath))
	}
	if unrouted, err := r.hook(context.DeadlineExceeded, nil).UnrouteUnanswered(context.Background()); err != nil || !unrouted ||
		readFile(t, configPath) != original {
		t.Fatalf("UnrouteUnanswered with no answer in time = %v, %v; config:\n%s", unrouted, err, readFile(t, configPath))
	}
}

// Only the health check's refused connection or its timeout count as no
// answer, as the real check reports them.
func TestOnlyNoAnswerCountsAsNoAnswer(t *testing.T) {
	token := strings.Repeat("k", 32)
	listen := func() (net.Listener, int) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		return listener, listener.Addr().(*net.TCPAddr).Port
	}
	closed, closedPort := listen()
	closed.Close()
	// launchd holds a job's port and starts the proxy on demand: until it
	// does, the connection waits unaccepted.
	_, waitingPort := listen()
	hangsUp, hangsUpPort := listen()
	go func() {
		for {
			conn, err := hangsUp.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	answers := func(status int, body string) int {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}))
		t.Cleanup(server.Close)
		port, _ := strconv.Atoi(server.URL[strings.LastIndex(server.URL, ":")+1:])
		return port
	}
	for _, check := range []struct {
		name     string
		port     int
		noAnswer bool
	}{
		{"nothing listens", closedPort, true},
		{"nothing accepts", waitingPort, true},
		{"the proxy", answers(http.StatusOK, "kontext codex proxy\n"), false},
		{"another server", answers(http.StatusNotFound, "404 page not found\n"), false},
		{"a hang-up", hangsUpPort, false},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		err := health(ctx, check.port, token)
		cancel()
		if noAnswer(err) != check.noAnswer || (err == nil) != (check.name == "the proxy") {
			t.Errorf("%s: health = %v, no answer %v", check.name, err, noAnswer(err))
		}
	}
}

// The job takes Codex's route away once its requests cannot reach OpenAI,
// and the daemon, whose health check only reaches the job, routes Codex again
// only once the job reaches OpenAI, after a while.
func TestTheRouteWaitsForTheJobToReachOpenAI(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o644)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)

	// While a daemon changes the route, the job leaves it to it.
	unlock, locked, err := lockFile(r.lockPath(), true)
	if err != nil || !locked {
		t.Fatal(err)
	}
	if taken, err := r.job(0).Unreachable(context.Background()); err != nil || taken || readFile(t, configPath) != routed {
		t.Fatalf("Unreachable during a change = %v, %v", taken, err)
	}
	unlock()
	if taken, err := r.job(0).Unreachable(context.Background()); err != nil || !taken {
		t.Fatalf("Unreachable = %v, %v", taken, err)
	}
	if info, _ := os.Stat(configPath); readFile(t, configPath) != original || info.Mode().Perm() != 0o644 {
		t.Fatalf("config once the job could not reach OpenAI (%v):\n%s", info.Mode().Perm(), readFile(t, configPath))
	}
	if held, err := r.job(0).Held(context.Background()); err != nil || held {
		t.Fatalf("Held after Unreachable = %v, %v", held, err)
	}

	// The daemon's next refreshes leave Codex routed directly, asking the
	// job nothing, and say why.
	bootstraps := r.launchd.ran("bootstrap")
	*r.healthy = false
	for _, later := range []time.Duration{0, unreachableWait - time.Minute} {
		*r.clock = later
		status, err := r.Enable(context.Background())
		if err != nil || status.Routed || !strings.HasPrefix(status.Skipped, "the Codex proxy could not reach OpenAI") || readFile(t, configPath) != original {
			t.Fatalf("Enable %v after = %+v, %v", later, status, err)
		}
	}
	if status := r.Status(context.Background()); !strings.HasPrefix(status.Skipped, "the Codex proxy could not reach OpenAI") {
		t.Fatalf("Status = %+v", status)
	}
	if r.launchd.ran("bootstrap") != bootstraps {
		t.Fatal("Enable reloaded the job while Codex waits")
	}

	// Then it asks again; the job still cannot reach OpenAI, so Codex waits
	// on.
	*r.healthy, *r.reaches, *r.clock = true, false, unreachableWait+time.Minute
	if status, err := r.Enable(context.Background()); err == nil || status.Routed || readFile(t, configPath) != original {
		t.Fatalf("Enable while the job cannot reach OpenAI = %+v, %v", status, err)
	}
	if status, err := r.Enable(context.Background()); err != nil || !strings.HasPrefix(status.Skipped, "the Codex proxy could not reach OpenAI") {
		t.Fatalf("Enable right after = %+v, %v", status, err)
	}
	*r.reaches, *r.clock = true, 2*unreachableWait+2*time.Minute
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed || readFile(t, configPath) != routed {
		t.Fatalf("Enable once the job reaches OpenAI = %+v, %v; config:\n%s", status, err, readFile(t, configPath))
	}
	if st := r.loadState(); !st.Unreachable.IsZero() || st.Holder == nil {
		t.Fatalf("state once routed again: %+v", st)
	}
	// A routed job is not asked again: its own requests tell.
	*r.reaches = false
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed {
		t.Fatalf("Enable while routed = %+v, %v", status, err)
	}
}

// A daemon that stops while the job checks that it reaches OpenAI learned
// nothing about the network, and requests that Codex processes send after the
// line went say nothing about the next route: neither holds the next daemon
// off.
func TestOnlyACompletedReachCheckOrATakenRouteHoldsCodexOff(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o644)
	stopping, stop := context.WithCancel(context.Background())
	stop()
	if status, err := r.Enable(stopping); !errors.Is(err, context.Canceled) || status.Routed {
		t.Fatalf("Enable as the daemon stops = %+v, %v", status, err)
	}
	if st := r.loadState(); !st.Unreachable.IsZero() {
		t.Fatalf("a stopping daemon held the next route off: %+v", st)
	}
	if status, err := r.daemon(t).Enable(context.Background()); err != nil || !status.Routed {
		t.Fatalf("Enable by the next daemon = %+v, %v", status, err)
	}

	if err := r.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if taken, err := r.job(0).Unreachable(context.Background()); err != nil || taken {
		t.Fatalf("Unreachable without a route = %v, %v", taken, err)
	}
	if st := r.loadState(); !st.Unreachable.IsZero() {
		t.Fatalf("draining requests held the next route off: %+v", st)
	}
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed {
		t.Fatalf("Enable after draining requests failed = %+v, %v", status, err)
	}
}

// A proxy that takes longer than five seconds to start, as a fresh copy of
// the binary on a busy Mac does, keeps its route: the health check waits as
// long as the hook does.
func TestASlowStartingProxyKeepsItsRoute(t *testing.T) {
	token := strings.Repeat("k", 32)
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5500 * time.Millisecond)
		if r.URL.Path == "/"+token+"/kontext-health" {
			_, _ = io.WriteString(w, "kontext codex proxy\n")
		}
	}))
	defer slow.Close()
	port, _ := strconv.Atoi(slow.URL[strings.LastIndex(slow.URL, ":")+1:])
	home := t.TempDir()
	configPath := filepath.Join(home, ".codex", "config.toml")
	routed, err := codexmanaged.AddRoute(original, BaseURL(port, token))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, configPath, routed, 0o600)
	hook := New(Options{Home: home, StateDir: filepath.Join(home, "state"), GOOS: "darwin"})
	if unrouted, err := hook.UnrouteUnanswered(context.Background()); err != nil || unrouted || readFile(t, configPath) != routed {
		t.Fatalf("UnrouteUnanswered with a slow proxy = %v, %v", unrouted, err)
	}
}

// Codex is routed through a job only once it reaches OpenAI, which it may
// never do from a network that needs a proxy it does not know; the job stays
// for whatever still calls it, until the drain.
func TestEnableRoutesOnlyThroughAJobThatReachesOpenAI(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o644)
	*r.reaches = false
	if status, err := r.Enable(context.Background()); err == nil || status.Routed || readFile(t, configPath) != original {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	if st := r.loadState(); st.Holder != nil || st.Unreachable.IsZero() || st.Port != testPort || !r.launchd.loaded {
		t.Fatalf("state: %+v, job loaded %v", st, r.launchd.loaded)
	}
	if done, err := r.Drain(context.Background()); err != nil || !done || r.launchd.loaded {
		t.Fatalf("Drain = %v, %v", done, err)
	}
}

// A route an administrator set in a layer of Codex's configuration keeps
// Codex as it is, as does a layer Kontext cannot read: Kontext's line goes,
// and comes back only once no such layer routes Codex.
func TestAnAdministratorsRouteKeepsCodexAsItIs(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o644)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)

	for _, admin := range []adminAnswer{
		{blocker: codexmanaged.Blocker{Setting: codexmanaged.SettingModelProvider, Text: "/etc/codex/requirements.toml sets model_provider"}},
		{err: errors.New("/etc/codex/config.toml: permission denied")},
	} {
		*r.admin = admin
		status, err := r.Enable(context.Background())
		want, reason := admin.blocker.Text, ReasonAdminModelProvider
		if admin.err != nil {
			want, reason = "Codex's administrator configuration cannot be read: "+admin.err.Error(), ReasonAdminConfigUnreadable
		}
		if err != nil || status.Routed || status.Skipped != want || status.Reason != reason {
			t.Fatalf("Enable with %+v = %+v, %v", admin, status, err)
		}
		if info, _ := os.Stat(configPath); readFile(t, configPath) != original || info.Mode().Perm() != 0o644 {
			t.Fatalf("config with %+v (%v):\n%s", admin, info.Mode().Perm(), readFile(t, configPath))
		}
		if status := r.Status(context.Background()); status.Routed || status.Skipped != want {
			t.Fatalf("Status with %+v = %+v", admin, status)
		}
	}

	*r.admin = adminAnswer{}
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed || readFile(t, configPath) != routed {
		t.Fatalf("Enable once no administrator routes Codex = %+v, %v", status, err)
	}
}

// A daemon that keeps its state elsewhere, as one restarted on another Kontext
// profile does, takes the route over on the port and token Codex reads, and
// reloads the job from its own state once. The job it replaces keeps the line
// while its lease runs.
func TestADaemonTakesOverARouteKeptElsewhere(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	writeFile(t, configPath, original, 0o600)
	profiles := filepath.Join(r.home, "Library", "Application Support", "Kontext", "profiles")
	local := filepath.Join(profiles, "local", "managed-observe", "codex-proxy")
	staging := filepath.Join(profiles, "staging", "managed-observe", "codex-proxy")
	if _, err := r.daemonIn(t, local).Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)
	token := strings.TrimSpace(readFile(t, TokenPath(local)))

	r.processes.run(os.Getpid(), time.Now())
	bootstraps := r.launchd.ran("bootstrap")
	if status, err := r.daemonIn(t, staging).Enable(context.Background()); err != nil || !status.Routed || status.Port != testPort ||
		readFile(t, configPath) != routed {
		t.Fatalf("Enable over a route kept elsewhere = %+v, %v; config:\n%s", status, err, readFile(t, configPath))
	}
	plist := readFile(t, filepath.Join(r.home, "Library", "LaunchAgents", Label+".plist"))
	if strings.TrimSpace(readFile(t, TokenPath(staging))) != token || strings.Contains(plist, local) ||
		!strings.Contains(plist, BinaryPath(staging)) || r.launchd.ran("bootstrap") != bootstraps+1 {
		t.Fatalf("the job after the takeover (%d bootstraps):\n%s", r.launchd.ran("bootstrap")-bootstraps, plist)
	}
	replaced := New(Options{Home: r.home, StateDir: local, GOOS: "darwin", ProcessStarted: r.processes.lookup})
	if held, err := replaced.Held(context.Background()); err != nil || !held || readFile(t, configPath) != routed {
		t.Fatalf("the replaced job's Held within its lease = %v, %v", held, err)
	}
}

// The job reaches OpenAI through the proxy the daemon was told to use, and
// the plist that names it is the person's alone.
func TestTheJobGetsTheDaemonsProxySettings(t *testing.T) {
	r := newTestRouter(t)
	writeFile(t, filepath.Join(r.home, ".codex", "config.toml"), original, 0o600)
	plistPath := filepath.Join(r.home, "Library", "LaunchAgents", Label+".plist")
	// An older build's plist, which anyone may read.
	writeFile(t, plistPath, "<plist/>\n", 0o644)
	r.env["HTTPS_PROXY"] = "http://kim:s3cr&t@proxy.example:3128"
	r.env["no_proxy"] = "localhost,.internal.example"
	r.env["HTTP_PROXY"] = ""
	r.env["ALL_PROXY"] = "socks5://proxy.example:1080"
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	plist := readFile(t, plistPath)
	want := "\t<key>EnvironmentVariables</key>\n\t<dict>\n" +
		"\t\t<key>HTTPS_PROXY</key>\n\t\t<string>http://kim:s3cr&amp;t@proxy.example:3128</string>\n" +
		"\t\t<key>no_proxy</key>\n\t\t<string>localhost,.internal.example</string>\n\t</dict>\n"
	if !strings.Contains(plist, want) || strings.Contains(plist, "HTTP_PROXY") || strings.Contains(plist, "ALL_PROXY") {
		t.Fatalf("plist:\n%s", plist)
	}
	if info, err := os.Stat(plistPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("plist mode = %v, %v", info.Mode().Perm(), err)
	}
	decoder := xml.NewDecoder(strings.NewReader(plist))
	for {
		if _, err := decoder.Token(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("plist is not XML: %v\n%s", err, plist)
		}
	}

	// A daemon started with other settings reloads the job with them, and
	// one started with none gives it macOS's, none here.
	bootstraps := r.launchd.ran("bootstrap")
	r.env = map[string]string{}
	if _, err := r.daemon(t).Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if plist := readFile(t, plistPath); strings.Contains(plist, "EnvironmentVariables") || r.launchd.ran("bootstrap") != bootstraps+1 {
		t.Fatalf("after a daemon without proxy settings (%d bootstraps):\n%s", r.launchd.ran("bootstrap")-bootstraps, plist)
	}
}

// The job found it could not reach OpenAI through the proxy settings it had:
// once it would get others, as when the Mac joins a network with a proxy, it
// is asked again at once. The same settings, or none that can be read, keep
// Codex waiting, and so does a job that is gone.
func TestOtherProxySettingsEndTheWait(t *testing.T) {
	r := newTestRouter(t)
	configPath := filepath.Join(r.home, ".codex", "config.toml")
	plistPath := filepath.Join(r.home, "Library", "LaunchAgents", Label+".plist")
	writeFile(t, configPath, original, 0o600)
	if _, err := r.Enable(context.Background()); err != nil {
		t.Fatal(err)
	}
	routed := readFile(t, configPath)
	waits := func(when string) {
		t.Helper()
		if status, err := r.Enable(context.Background()); err != nil || !strings.HasPrefix(status.Skipped, "the Codex proxy could not reach OpenAI") ||
			readFile(t, configPath) != original {
			t.Fatalf("Enable %s = %+v, %v", when, status, err)
		}
	}
	if taken, err := r.job(0).Unreachable(context.Background()); err != nil || !taken {
		t.Fatalf("Unreachable = %v, %v", taken, err)
	}
	// A job asked would not reach OpenAI either.
	*r.reaches = false
	waits("with the same settings")
	r.scutil.err = errors.New("exit status 1")
	waits("once scutil fails")

	// macOS's proxies end the wait. The daemon reads them once, so the job
	// gets the ones that ended it, even if scutil fails right after.
	r.scutil.output, r.scutil.err, *r.reaches = manualProxies, nil, true
	r.scutil.failAfter = r.scutil.asked + 1
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed || readFile(t, configPath) != routed {
		t.Fatalf("Enable through macOS's proxies = %+v, %v", status, err)
	}
	if env := jobEnv(readFile(t, plistPath)); !slices.Equal(env, manualEnv) {
		t.Fatalf("the job's settings = %q", env)
	}
	r.scutil.failAfter = 0

	if taken, err := r.job(0).Unreachable(context.Background()); err != nil || !taken {
		t.Fatalf("Unreachable through macOS's proxies = %v, %v", taken, err)
	}
	*r.reaches = false
	waits("through macOS's proxies still")
	if drained, err := r.Drain(context.Background()); err != nil || !drained {
		t.Fatalf("Drain = %v, %v", drained, err)
	}
	waits("once the job is gone")
}

// The daemon's own proxy settings, in either case, win over macOS's, which
// nobody asks for then.
func TestTheDaemonsProxySettingsWinOverMacOSs(t *testing.T) {
	r := newTestRouter(t)
	writeFile(t, filepath.Join(r.home, ".codex", "config.toml"), original, 0o600)
	r.scutil.output = manualProxies
	r.env["https_proxy"] = "http://daemon-proxy.example:3128"
	if status, err := r.Enable(context.Background()); err != nil || !status.Routed {
		t.Fatalf("Enable = %+v, %v", status, err)
	}
	plist := readFile(t, filepath.Join(r.home, "Library", "LaunchAgents", Label+".plist"))
	if env := jobEnv(plist); !slices.Equal(env, [][2]string{{"https_proxy", "http://daemon-proxy.example:3128"}}) || r.scutil.asked != 0 {
		t.Fatalf("the job's settings %q, macOS's asked for %d times; plist:\n%s", env, r.scutil.asked, plist)
	}
}

// On a Mac set to use manual proxies, the job reaches OpenAI through them.
// Each reload cuts Codex's streams, so the job is reloaded only once they
// change: not for anything else scutil prints, nor when they cannot be read.
func TestTheJobGetsMacOSsManualProxies(t *testing.T) {
	r := newTestRouter(t)
	writeFile(t, filepath.Join(r.home, ".codex", "config.toml"), original, 0o600)
	plistPath := filepath.Join(r.home, "Library", "LaunchAgents", Label+".plist")
	// enable has the daemon route Codex once scutil printed output or failed
	// with err, and tells what the job got and how many times it reloaded.
	enable := func(output string, err error) ([][2]string, int) {
		t.Helper()
		bootstraps := r.launchd.ran("bootstrap")
		r.scutil.output, r.scutil.err = output, err
		if status, err := r.Enable(context.Background()); err != nil || !status.Routed {
			t.Fatalf("Enable = %+v, %v", status, err)
		}
		return jobEnv(readFile(t, plistPath)), r.launchd.ran("bootstrap") - bootstraps
	}
	if env, _ := enable(manualProxies, nil); !slices.Equal(env, manualEnv) {
		t.Fatalf("the job's settings = %q; plist:\n%s", env, readFile(t, plistPath))
	}

	otherwise := strings.NewReplacer("ExcludeSimpleHostnames : 1", "ExcludeSimpleHostnames : 0",
		"SOCKSEnable : 0", "SOCKSEnable : 1\n  SOCKSPort : 1080\n  SOCKSProxy : socks.example",
		"ProxyAutoConfigEnable : 0", "ProxyAutoConfigEnable : 0\n  ProxyAutoConfigURLString : http://wpad.example/proxy.pac",
		"utun4", "utun5").Replace(manualProxies)
	for _, answer := range []struct {
		output string
		err    error
	}{{otherwise, nil}, {"", errors.New("exit status 1")}, {"No proxy configuration available\n", nil}} {
		if env, reloads := enable(answer.output, answer.err); reloads != 0 || !slices.Equal(env, manualEnv) {
			t.Fatalf("once scutil printed %q, %v: the job's settings = %q, %d reloads", answer.output, answer.err, env, reloads)
		}
	}

	// Another proxy reloads the job with it, and a PAC file leaves it none.
	moved := strings.ReplaceAll(manualProxies, "HTTPSProxy : proxy.example", "HTTPSProxy : proxy.office.example")
	if env, reloads := enable(moved, nil); reloads != 1 || len(env) != 3 || env[0] != [2]string{"HTTPS_PROXY", "http://proxy.office.example:3128"} {
		t.Fatalf("on another proxy: the job's settings = %q, %d reloads", env, reloads)
	}
	if env, reloads := enable(pacProxies, nil); reloads != 1 || env != nil || strings.Contains(readFile(t, plistPath), "EnvironmentVariables") {
		t.Fatalf("on a PAC file: the job's settings = %q, %d reloads", env, reloads)
	}
	if env, reloads := enable(noProxies, nil); reloads != 0 || env != nil {
		t.Fatalf("on no proxy: the job's settings = %q, %d reloads", env, reloads)
	}
}
