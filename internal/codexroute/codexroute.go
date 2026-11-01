// Package codexroute sends Codex's model traffic through the Kontext Codex
// proxy while the endpoint's tool output compaction switch is on, on macOS.
//
// It owns three things and the order they change in: the proxy's launchd job,
// for which launchd holds a loopback port and starts the proxy on demand from
// a copy of the daemon's binary the job keeps for itself; the openai_base_url
// line in ~/.codex/config.toml that points Codex at the port; and the drain in
// between. The line goes only once the proxy answers on the port, and the job
// goes only once no Codex process that may have read the line is left, so no
// Codex thread is ever left calling a port nobody holds.
//
// The daemon holds the line on a lease it renews. Once no daemon renews it,
// because the daemon stopped or a build without the proxy replaced it, the
// proxy takes the line away itself (see Router.Held): the route never
// outlives the daemons that know it.
package codexroute

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kontext-security/kontext/internal/agenthooks"
	"github.com/kontext-security/kontext/internal/codexmanaged"
	"github.com/kontext-security/kontext/internal/codexproxy"
)

// Label is the proxy job's launchd label.
const Label = "security.kontext.codex-proxy"

// IdleExit is how long the proxy runs without a connection before it exits;
// launchd starts it again for the next one.
const IdleExit = 10 * time.Minute

// unloadWait is how long the router waits for launchd to let the job go
// after bootout.
const unloadWait = 5 * time.Second

// LeaseRenewal is how often the daemon renews its hold on the route, and
// leaseGrace how long the route outlives the daemon that last renewed it,
// long enough for a daemon that restarts to renew it again.
const (
	LeaseRenewal = time.Minute
	leaseGrace   = 10 * time.Minute
)

// StateDir is where the proxy keeps its token, port and decisions, next to
// the daemon's database.
func StateDir(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "codex-proxy")
}

// TokenPath, DecisionsDir and BinaryPath are the proxy's token, its decision
// store and the job's binary in a state directory.
func TokenPath(stateDir string) string    { return filepath.Join(stateDir, "token") }
func DecisionsDir(stateDir string) string { return filepath.Join(stateDir, "decisions") }
func BinaryPath(stateDir string) string   { return filepath.Join(stateDir, "bin", "kontext") }

// BaseURL is the openai_base_url that reaches the proxy.
func BaseURL(port int, token string) string {
	return "http://127.0.0.1:" + strconv.Itoa(port) + "/" + token + "/backend-api/codex"
}

// Options locate what the router changes. The seams default to the real
// thing.
type Options struct {
	// Home is the person's home directory, which holds ~/.codex,
	// ~/Library/LaunchAgents and ~/Library/Logs.
	Home string
	// Binary is the daemon's own kontext binary, opened when the daemon
	// starts: the job runs a copy of it (see BinaryPath), since an update or
	// a downgrade may replace the file at its path with a build that has no
	// proxy. Only Enable needs it.
	Binary *os.File
	// StateDir is the proxy's state directory (see StateDir), and Socket the
	// daemon's socket.
	StateDir string
	Socket   string
	// Label is the job's launchd label, Label unless a test needs another.
	Label string
	// Upstream and APIUpstream, when set, are where the job forwards the
	// requests of ChatGPT logins and of API keys instead of the Codex backend
	// and the OpenAI API; tests point them at mocks.
	Upstream    string
	APIUpstream string
	// LeaseGrace is how long the route outlives the daemon that last renewed
	// it.
	LeaseGrace time.Duration

	GOOS string
	// Launchctl runs launchctl and fails when it exits non-zero.
	Launchctl func(ctx context.Context, args ...string) error
	// Health checks that the proxy, not another process, answers on port.
	Health func(ctx context.Context, port int, token string) error
	// CodexSince counts the person's Codex processes started before t.
	CodexSince func(t time.Time) (int, error)
	// ProcessStarted reports when process pid started, or false when none
	// runs.
	ProcessStarted func(pid int) (time.Time, bool)
	// FreePort picks a loopback port nothing listens on.
	FreePort func() (int, error)
	Now      func() time.Time
}

// Router changes the route; its methods are safe to call from any goroutine.
type Router struct {
	opts Options
	mu   sync.Mutex
}

// Status is what doctor reports about the route.
type Status struct {
	// Routed reports that config.toml points Codex at the job's port.
	Routed bool
	// Skipped says why Kontext leaves Codex's traffic alone, when it does.
	Skipped string
	Loaded  bool
	Port    int
	// Answering reports that the proxy answers on the port Codex is routed
	// to; a route without it leaves Codex retrying forever.
	Answering bool
	// Held reports that a daemon holds the route (see Router.Held).
	Held bool
	// Draining counts the Codex processes from before the line went that may
	// still call the job, which therefore stays.
	Draining int
}

// state is what the router keeps in route.json.
type state struct {
	Port int `json:"port,omitempty"`
	// UnroutedAt is when the line last went: Codex processes started before
	// it may still call the job.
	UnroutedAt time.Time `json:"unroutedAt,omitzero"`
	// CreatedConfig is set when the router created config.toml, which goes
	// again with the line when nothing else is in it.
	CreatedConfig bool `json:"createdConfig,omitempty"`
	// ConfigMode is config.toml's mode before the router kept it from other
	// users, to restore with the line; 0 when it was private already.
	ConfigMode uint32 `json:"configMode,omitempty"`
	// Failures counts the health checks in a row the routed proxy missed.
	Failures int `json:"failures,omitempty"`
	// Holder is the daemon that holds the route, while it is routed.
	Holder *holder `json:"holder,omitempty"`
	// Binary names the daemon binary the job's copy was made from.
	Binary string `json:"binary,omitempty"`
}

// holder is a daemon's hold on the route: it lasts while that daemon runs,
// and until Until after it stops.
type holder struct {
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	Until   time.Time `json:"until"`
}

// maxHealthFailures is how many health checks in a row the routed proxy may
// miss before Codex is routed directly again.
const maxHealthFailures = 3

func New(opts Options) *Router {
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.Label == "" {
		opts.Label = Label
	}
	if opts.LeaseGrace == 0 {
		opts.LeaseGrace = leaseGrace
	}
	if opts.ProcessStarted == nil {
		opts.ProcessStarted = processStarted
	}
	if opts.Launchctl == nil {
		opts.Launchctl = runLaunchctl
	}
	if opts.Health == nil {
		opts.Health = health
	}
	if opts.CodexSince == nil {
		opts.CodexSince = codexSince
	}
	if opts.FreePort == nil {
		opts.FreePort = freePort
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Router{opts: opts}
}

func (r *Router) configPath() string { return filepath.Join(r.opts.Home, ".codex", "config.toml") }
func (r *Router) plistPath() string {
	return filepath.Join(r.opts.Home, "Library", "LaunchAgents", r.opts.Label+".plist")
}
func (r *Router) logPath() string {
	return filepath.Join(r.opts.Home, "Library", "Logs", "Kontext", "codex-proxy.log")
}
func (r *Router) statePath() string { return filepath.Join(r.opts.StateDir, "route.json") }
func (r *Router) lockPath() string  { return filepath.Join(r.opts.StateDir, "route.lock") }

// lock takes the lock the router shares with the proxy job, which takes the
// line away itself once no daemon holds it (see Held). r.mu must be held,
// and the lock is never taken twice.
func (r *Router) lock() (func(), error) {
	unlock, _, err := lockFile(r.lockPath(), true)
	return unlock, err
}

// Enable routes Codex through the proxy: it starts the job and, once the
// proxy answers on its port, writes the config line. It leaves Codex alone,
// and takes its own line away, when the person routes Codex's model traffic
// themselves.
func (r *Router) Enable(ctx context.Context) (Status, error) {
	if r.opts.GOOS != "darwin" {
		return Status{Skipped: "the Codex proxy runs on macOS only"}, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	config, err := readConfig(r.configPath())
	if err != nil {
		return Status{}, err
	}
	if skip := r.skip(config.content); skip != "" {
		return Status{Skipped: skip}, r.unrouteLocked()
	}
	unlock, err := r.lock()
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	// The proxy job may have taken the line away meanwhile.
	if config, err = readConfig(r.configPath()); err != nil {
		return Status{}, err
	}
	st := r.loadState()
	token, err := r.ensureToken()
	if err != nil {
		return Status{}, err
	}
	// The line Codex reads names the job: keep its port and token, so every
	// Codex process that read it keeps reaching the proxy.
	port, routedToken, routed := parseBaseURL(codexmanaged.Route(config.content))
	if routed {
		if routedToken != token {
			if err := writePrivate(r.opts.StateDir, TokenPath(r.opts.StateDir), []byte(routedToken+"\n")); err != nil {
				return Status{}, err
			}
			token = routedToken
		}
		st.Port = port
	}
	if st.Port == 0 {
		if st.Port, err = r.opts.FreePort(); err != nil {
			return Status{}, err
		}
	}
	if err := r.ensureBinary(&st); err != nil {
		if routed {
			return Status{}, errors.Join(err, r.unroute())
		}
		return Status{}, err
	}
	// The hold comes before the line, which the proxy job would otherwise
	// find unheld and take away.
	st.Holder = r.holder()
	if err := r.saveState(st); err != nil {
		return Status{}, err
	}
	if err := r.ensureJob(ctx, st.Port); err != nil {
		if routed {
			// Codex must never be left calling a port nobody holds.
			return Status{}, errors.Join(fmt.Errorf("codex proxy job not loaded: %w", err), r.unroute())
		}
		return Status{}, err
	}
	if err := r.opts.Health(ctx, st.Port, token); err != nil {
		if !routed {
			// Nothing reads this port yet, and another process may hold it:
			// the next try takes a new one.
			_ = r.unloadJob(ctx)
			st.Port, st.Holder = 0, nil
			_ = r.saveState(st)
			return Status{}, fmt.Errorf("codex proxy did not answer on its port: %w", err)
		}
		// Codex reads this port: the job stays, since launchd starts the
		// proxy on demand, and the route goes only after several misses.
		if st.Failures++; st.Failures < maxHealthFailures {
			_ = r.saveState(st)
			return Status{}, fmt.Errorf("codex proxy did not answer on its port (%d in a row): %w", st.Failures, err)
		}
		st.Failures = 0
		_ = r.saveState(st)
		return Status{}, errors.Join(fmt.Errorf("codex proxy did not answer %d times in a row, so Codex is routed directly again: %w",
			maxHealthFailures, err), r.unroute())
	}
	next, err := codexmanaged.AddRoute(config.content, BaseURL(st.Port, token))
	if err != nil {
		return Status{}, err
	}
	if next != config.content {
		if err := config.write(next); err != nil {
			return Status{}, err
		}
		if !config.exists {
			st.CreatedConfig = true
		}
	}
	// The file holds the token now: keep it from other users.
	if config.exists && config.mode&0o077 != 0 && st.ConfigMode == 0 {
		if err := os.Chmod(config.path, config.mode&^0o077); err == nil {
			st.ConfigMode = uint32(config.mode)
		}
	}
	st.UnroutedAt, st.Failures = time.Time{}, 0
	if err := r.saveState(st); err != nil {
		return Status{}, err
	}
	return Status{Routed: true, Loaded: true, Answering: true, Port: st.Port}, nil
}

// Disable takes the config line away, so new Codex threads call OpenAI
// directly. The job stays, passing requests through, for the threads that
// already read the line, until Drain finds them gone. Without the line,
// nothing in ~/.codex changes.
func (r *Router) Disable(context.Context) error {
	if r.opts.GOOS != "darwin" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.unrouteLocked()
}

// unrouteLocked is unroute under the lock, which it takes only when there is
// a line to take away.
func (r *Router) unrouteLocked() error {
	config, err := readConfig(r.configPath())
	if err != nil || codexmanaged.Route(config.content) == "" {
		return err
	}
	unlock, err := r.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return r.unroute()
}

// Renew renews the daemon's hold on the route while Codex is routed; the
// daemon calls it every LeaseRenewal.
func (r *Router) Renew(context.Context) error {
	if r.opts.GOOS != "darwin" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if config, err := readConfig(r.configPath()); err != nil || codexmanaged.Route(config.content) == "" {
		return err
	}
	unlock, err := r.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if config, err := readConfig(r.configPath()); err != nil || codexmanaged.Route(config.content) == "" {
		return err
	}
	st := r.loadState()
	st.Holder = r.holder()
	return r.saveState(st)
}

// Held reports whether a daemon that knows the proxy holds Codex's route: one
// runs that renewed it, or the last renewal is recent enough to cover a
// restart. Once none does, because the daemon stopped or a build without the
// proxy replaced it, Held takes the config line away, so Codex processes
// that start from then on call OpenAI directly. The proxy job asks before
// each request, and passes the requests of the processes that read the line
// through unchanged.
func (r *Router) Held(context.Context) (bool, error) {
	if r.opts.GOOS != "darwin" {
		return false, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	unlock, locked, err := lockFile(r.lockPath(), false)
	if err != nil {
		return false, err
	}
	if !locked {
		// A daemon is changing the route as we speak.
		return true, nil
	}
	defer unlock()
	if r.held(r.loadState().Holder) {
		return true, nil
	}
	return false, r.unroute()
}

// holder is this process's hold on the route.
func (r *Router) holder() *holder {
	pid := os.Getpid()
	started, _ := r.opts.ProcessStarted(pid)
	return &holder{PID: pid, Started: started, Until: r.opts.Now().Add(r.opts.LeaseGrace)}
}

// held reports whether h holds the route: its daemon runs, or it stopped
// less than the grace ago.
func (r *Router) held(h *holder) bool {
	if h == nil {
		return false
	}
	if started, running := r.opts.ProcessStarted(h.PID); running && !h.Started.IsZero() && started.Equal(h.Started) {
		return true
	}
	return r.opts.Now().Before(h.Until)
}

// unroute takes the config line away and notes when. r.mu and the lock must
// be held.
func (r *Router) unroute() error {
	config, err := readConfig(r.configPath())
	if err != nil || codexmanaged.Route(config.content) == "" {
		return err
	}
	next, err := codexmanaged.RemoveRoute(config.content)
	if err != nil {
		return err
	}
	st := r.loadState()
	if st.CreatedConfig && strings.TrimSpace(next) == "" {
		err = os.Remove(config.path)
		st.CreatedConfig = false
	} else {
		err = config.write(next)
		if err == nil && st.ConfigMode != 0 {
			err = os.Chmod(config.path, fs.FileMode(st.ConfigMode))
		}
	}
	if err != nil {
		return err
	}
	st.UnroutedAt, st.ConfigMode, st.Holder = r.opts.Now(), 0, nil
	return r.saveState(st)
}

// Drain unloads the job once Codex is no longer routed to it and no Codex
// process that started while it was is still running. It reports whether
// the job is gone.
func (r *Router) Drain(ctx context.Context) (bool, error) {
	if r.opts.GOOS != "darwin" {
		return true, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	config, err := readConfig(r.configPath())
	if err != nil || codexmanaged.Route(config.content) != "" {
		return false, err
	}
	// No plist, no job: the daemon checks this every minute, without asking
	// launchd.
	if _, err := os.Stat(r.plistPath()); errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	unlock, err := r.lock()
	if err != nil {
		return false, err
	}
	defer unlock()
	if left, err := r.draining(); err != nil || left > 0 {
		return false, err
	}
	return true, r.removeJob(ctx)
}

// Remove takes everything away for uninstall, in order: the config line;
// then, once the Codex processes that may have read it are gone or wait runs
// out, the job and the proxy's state. It returns how many of them were left.
func (r *Router) Remove(ctx context.Context, wait time.Duration) (int, error) {
	if r.opts.GOOS != "darwin" {
		return 0, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	config, err := readConfig(r.configPath())
	if err != nil {
		return 0, err
	}
	_, statErr := os.Stat(r.plistPath())
	if codexmanaged.Route(config.content) == "" && errors.Is(statErr, fs.ErrNotExist) && !r.loaded(ctx) {
		// Never routed, or already drained: nothing can still call the job.
		return 0, os.RemoveAll(r.opts.StateDir)
	}
	unlock, err := r.lock()
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := r.unroute(); err != nil {
		return 0, err
	}
	deadline := r.opts.Now().Add(wait)
	left, err := r.draining()
	for err == nil && left > 0 && r.opts.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return left, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
		left, err = r.draining()
	}
	if err != nil {
		return 0, err
	}
	if err := r.removeJob(ctx); err != nil {
		return left, err
	}
	return left, os.RemoveAll(r.opts.StateDir)
}

// Status reports the route as it stands, changing nothing.
func (r *Router) Status(ctx context.Context) Status {
	if r.opts.GOOS != "darwin" {
		return Status{Skipped: "the Codex proxy runs on macOS only"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	st := r.loadState()
	status := Status{Port: st.Port, Loaded: r.loaded(ctx)}
	config, err := readConfig(r.configPath())
	if err != nil {
		status.Skipped = err.Error()
		return status
	}
	data, _ := os.ReadFile(TokenPath(r.opts.StateDir))
	token := strings.TrimSpace(string(data))
	route := codexmanaged.Route(config.content)
	status.Routed = route != ""
	if status.Routed {
		status.Answering = st.Port != 0 && route == BaseURL(st.Port, token) && r.opts.Health(ctx, st.Port, token) == nil
		status.Held = r.held(st.Holder)
	} else {
		status.Skipped = r.skip(config.content)
		if status.Loaded {
			status.Draining, _ = r.draining()
		}
	}
	return status
}

// skip says why Codex's traffic stays as it is, or "". How Codex is signed in
// never matters: the proxy sends each request where its credentials belong.
func (r *Router) skip(config string) string {
	blocker, err := codexmanaged.RouteBlocker(config)
	if err != nil {
		return "~/.codex/config.toml does not parse"
	}
	return blocker
}

// draining counts the Codex processes that may still call the job. r.mu must
// be held.
func (r *Router) draining() (int, error) {
	since := r.loadState().UnroutedAt
	if since.IsZero() {
		// When the line went is unknown: wait for every Codex process.
		since = r.opts.Now()
	}
	return r.opts.CodexSince(since)
}

func (r *Router) loadState() state {
	var st state
	if data, err := os.ReadFile(r.statePath()); err == nil {
		_ = json.Unmarshal(data, &st)
	}
	return st
}

func (r *Router) saveState(st state) error {
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writePrivate(r.opts.StateDir, r.statePath(), data)
}

func (r *Router) ensureToken() (string, error) {
	return EnsureToken(r.opts.StateDir)
}

// EnsureToken returns the proxy's token in stateDir, made the first time.
func EnsureToken(stateDir string) (string, error) {
	if data, err := os.ReadFile(TokenPath(stateDir)); err == nil {
		if token := strings.TrimSpace(string(data)); len(token) >= 32 {
			return token, nil
		}
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	token := "kx" + hex.EncodeToString(random)
	return token, writePrivate(stateDir, TokenPath(stateDir), []byte(token+"\n"))
}

// config is ~/.codex/config.toml as read.
type config struct {
	path    string
	content string
	mode    fs.FileMode
	exists  bool
}

func readConfig(path string) (config, error) {
	c := config{path: path, mode: 0o600}
	info, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	c.content, c.mode, c.exists = string(data), info.Mode().Perm(), true
	return c, nil
}

// write replaces the file through a temporary one, keeping its mode, and
// through a symlink to the file it names.
func (c config) write(content string) error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	return agenthooks.WriteRawFile(c.path, []byte(content))
}

// parseBaseURL reads the port and token of a BaseURL.
func parseBaseURL(baseURL string) (int, string, bool) {
	rest, ok := strings.CutPrefix(baseURL, "http://127.0.0.1:")
	if !ok {
		return 0, "", false
	}
	portText, rest, _ := strings.Cut(rest, "/")
	token, suffix, _ := strings.Cut(rest, "/")
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 || len(token) < 32 || suffix != "backend-api/codex" {
		return 0, "", false
	}
	return port, token, true
}

// writePrivate writes a file only its owner can read, in a directory only
// its owner can enter.
func writePrivate(dir, path string, data []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".codex-proxy-*.tmp")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	err = temporary.Chmod(0o600)
	if err == nil {
		_, err = temporary.Write(data)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

// ensureBinary gives the job its own copy of the daemon's binary, made again
// once the daemon runs another build. launchd runs the copy: an update, a
// downgrade or a Homebrew cleanup may replace or delete the file the daemon
// started from, and a job whose binary is gone or has no proxy leaves Codex
// reconnecting to a port nobody answers.
func (r *Router) ensureBinary(st *state) error {
	if r.opts.Binary == nil {
		return errors.New("no kontext binary to run the Codex proxy from")
	}
	info, err := r.opts.Binary.Stat()
	if err != nil {
		return err
	}
	id := fileIdentity(info)
	if _, err := os.Stat(BinaryPath(r.opts.StateDir)); err == nil && id != "" && id == st.Binary {
		return nil
	}
	if err := installBinary(r.opts.Binary, BinaryPath(r.opts.StateDir)); err != nil {
		return fmt.Errorf("copy the kontext binary for the Codex proxy: %w", err)
	}
	st.Binary = id
	return nil
}

// ensureJob writes the job's plist and (re)loads the job when either changed.
func (r *Router) ensureJob(ctx context.Context, port int) error {
	plist := renderPlist(job{label: r.opts.Label, binary: BinaryPath(r.opts.StateDir), port: port, home: r.opts.Home,
		stateDir: r.opts.StateDir, socket: r.opts.Socket, upstream: r.opts.Upstream, apiUpstream: r.opts.APIUpstream, logPath: r.logPath()})
	current, _ := os.ReadFile(r.plistPath())
	loaded := r.loaded(ctx)
	if string(current) == plist && loaded {
		return nil
	}
	for _, dir := range []string{filepath.Dir(r.plistPath()), filepath.Dir(r.logPath())} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(r.plistPath(), []byte(plist), 0o644); err != nil {
		return err
	}
	if loaded {
		if err := r.unloadJob(ctx); err != nil {
			return err
		}
	}
	return r.opts.Launchctl(ctx, "bootstrap", r.domain(), r.plistPath())
}

func (r *Router) removeJob(ctx context.Context) error {
	if err := r.unloadJob(ctx); err != nil {
		return err
	}
	if err := os.Remove(r.plistPath()); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// The job's binary goes with it.
	return os.RemoveAll(filepath.Dir(BinaryPath(r.opts.StateDir)))
}

// unloadJob takes the job out of launchd, and returns once launchd let it
// go: bootout may return before that, and a bootstrap fails until then.
func (r *Router) unloadJob(ctx context.Context) error {
	if !r.loaded(ctx) {
		return nil
	}
	err := r.opts.Launchctl(ctx, "bootout", r.domain()+"/"+r.opts.Label)
	for start := time.Now(); r.loaded(ctx); time.Sleep(50 * time.Millisecond) {
		if time.Since(start) > unloadWait {
			return errors.Join(fmt.Errorf("launchd still holds the Codex proxy job %s after bootout", unloadWait), err)
		}
	}
	return nil
}

func (r *Router) loaded(ctx context.Context) bool {
	return r.opts.Launchctl(ctx, "print", r.domain()+"/"+r.opts.Label) == nil
}

func (r *Router) domain() string {
	return "gui/" + strconv.Itoa(os.Getuid())
}

func runLaunchctl(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/launchctl", args...)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run()
}

func health(ctx context.Context, port int, token string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/"+token+codexproxy.HealthRoute, nil)
	if err != nil {
		return err
	}
	// No keep-alive: an open connection would keep the proxy from its idle
	// exit.
	response, err := (&http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}).Do(request)
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		// The URL holds the token, and the error goes to the daemon's log.
		err = urlErr.Err
	}
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(response.Body, 256))
	if response.StatusCode != http.StatusOK || string(body) != codexproxy.HealthBody {
		return fmt.Errorf("unexpected answer %d", response.StatusCode)
	}
	return nil
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
