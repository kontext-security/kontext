package setup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/autostart"
	"github.com/kontext-security/kontext/internal/credstore"
	"github.com/kontext-security/kontext/internal/hookinstall"
	"github.com/kontext-security/kontext/internal/installation"
	"github.com/kontext-security/kontext/internal/managedconfig"
)

// windowsRun is what a run of the Windows flow did to the user's session,
// recorded by fakes of its seams, on any OS.
type windowsRun struct {
	stored     map[string]string
	hooks      []hookinstall.Options
	hooksGone  int
	autostart  string
	started    []string
	binary     string
	daemon     string
	failAt     string
	storeError error
	stops      int
	// stoppedProgram is the daemon program the last stop was limited to.
	stoppedProgram string
	// stopError makes every stop fail.
	stopError error
	delError  error
}

func newWindowsRun(t *testing.T, h *harness) *windowsRun {
	t.Helper()
	run := &windowsRun{stored: map[string]string{}}
	bin := filepath.Join(h.home, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	run.binary, run.daemon = filepath.Join(bin, "kontext.exe"), filepath.Join(bin, windowsDaemonName)
	for _, program := range []string{run.binary, run.daemon} {
		if err := os.WriteFile(program, []byte("x"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	overrideVar(t, &goos, "windows")
	overrideVar(t, &executablePath, func() (string, error) { return run.binary, nil })
	overrideVar(t, &systemConfigPath, filepath.Join(h.home, "ProgramData", "Kontext", "managed.json"))
	overrideVar(t, &userHome, func() (string, error) { return h.home, nil })
	overrideVar(t, &storeWindowsToken, func(name, secret string) error {
		if run.storeError != nil {
			return run.storeError
		}
		run.stored[name] = secret
		return nil
	})
	overrideVar(t, &readWindowsToken, func(name string) (string, error) {
		secret, ok := run.stored[name]
		if !ok {
			return "", credstore.ErrNotFound
		}
		return secret, nil
	})
	overrideVar(t, &deleteWindowsToken, func(name string) error {
		if run.delError != nil {
			return run.delError
		}
		if _, ok := run.stored[name]; !ok {
			return credstore.ErrNotFound
		}
		delete(run.stored, name)
		return nil
	})
	overrideVar(t, &stopWindowsDaemon, func(program string) (bool, error) {
		run.stops++
		run.stoppedProgram = program
		if run.stopError != nil {
			return false, run.stopError
		}
		// A daemon runs once setup started one, until a stop ends it.
		running := len(run.started) > 0
		run.started = nil
		return running, nil
	})
	overrideVar(t, &readWindowsAutostart, func() (string, error) {
		if run.autostart == "" {
			return "", nil
		}
		return autostart.Command(run.autostart), nil
	})
	overrideVar(t, &installWindowsHooks, func(opts hookinstall.Options) error {
		if run.failAt == "hooks" {
			return errors.New("hooks failed")
		}
		run.hooks = append(run.hooks, opts)
		reportClaudeHooks(opts, "write")
		return nil
	})
	overrideVar(t, &removeWindowsHooks, func(opts hookinstall.Options) error {
		run.hooksGone++
		// The installer writes the file only when it held Kontext's hooks.
		if len(run.hooks) > 0 && run.hooksGone == 1 {
			reportClaudeHooks(opts, "write")
		} else {
			reportClaudeHooks(opts, "skip")
		}
		return nil
	})
	overrideVar(t, &setWindowsAutostart, func(daemon string) error {
		if run.failAt == "autostart" {
			return errors.New("autostart failed")
		}
		run.autostart = daemon
		return nil
	})
	overrideVar(t, &delWindowsAutostart, func() error { run.autostart = ""; return nil })
	overrideVar(t, &startWindowsDaemon, func(program string, args ...string) error {
		if run.failAt == "start" {
			return errors.New("start failed")
		}
		run.started = append([]string{program}, args...)
		return nil
	})
	return run
}

func TestRunWindowsStoresTheKeyWritesTheConfigAndStartsTheAgent(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	server := pingServer(t, "tok-123")
	opts := h.options("tok-123", server)
	var out bytes.Buffer
	opts.Stdout = &out

	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v\n%s", err, out.String())
	}
	if got := run.stored[WindowsCredentialName]; got != "tok-123" {
		t.Errorf("stored key = %q, want the install key under %s", got, WindowsCredentialName)
	}
	loaded, err := managedconfig.LoadFile(managedconfig.LegacyUserPath())
	if err != nil {
		t.Fatalf("the written config does not load: %v", err)
	}
	if ref := loaded.Config.Credentials.InstallTokenRef.String(); ref != "credential:"+WindowsCredentialName {
		t.Errorf("config's key reference = %q", ref)
	}
	if loaded.Config.Mode != managedconfig.ModeRemote {
		t.Errorf("config's mode = %q, want remote", loaded.Config.Mode)
	}
	if strings.Contains(out.String(), "tok-123") {
		t.Errorf("the output shows the install key:\n%s", out.String())
	}
	if len(run.hooks) != 1 || run.hooks[0].Scope != hookinstall.User || run.hooks[0].Binary != run.binary || run.hooks[0].Home != h.home {
		t.Errorf("hooks installed with %+v, want the user's hooks naming %s", run.hooks, run.binary)
	}
	if run.autostart != run.daemon {
		t.Errorf("autostart = %q, want %s", run.autostart, run.daemon)
	}
	if want := []string{run.daemon, "managed-observe-daemon"}; strings.Join(run.started, " ") != strings.Join(want, " ") {
		t.Errorf("started %q, want %q", run.started, want)
	}
}

// A machine-wide install wins over a user's, so setup beside one would write
// a config nothing reads.
func TestRunWindowsRefusesBesideAMachineWideInstall(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	if err := os.MkdirAll(filepath.Dir(systemConfigPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(systemConfigPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := pingServer(t, "tok")
	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "managed by your organization") {
		t.Fatalf("Run() = %v, want a refusal that names the machine-wide install", err)
	}
	if len(run.stored) != 0 || len(run.hooks) != 0 || run.autostart != "" {
		t.Errorf("the refused run wrote: key %v, hooks %v, autostart %q", run.stored, run.hooks, run.autostart)
	}
}

func TestRunWindowsRefusesProfiles(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	newWindowsRun(t, h)
	server := pingServer(t, "tok")
	opts := h.options("tok", server)
	opts.Profile = "work"
	if err := Run(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "profiles are not available on Windows") {
		t.Fatalf("Run() = %v, want a refusal of the profile", err)
	}
}

// A session without a credential store (SSH signed in with a key) can't keep
// the key. The run says what to do and writes nothing.
func TestRunWindowsSaysWhenTheSessionHasNoStore(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	run.storeError = credstore.ErrNoLogonSession
	allowLoopback(t)
	server := pingServer(t, "tok")
	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "desktop session") {
		t.Fatalf("Run() = %v, want it to send the user to a desktop session", err)
	}
	if _, statErr := os.Stat(managedconfig.LegacyUserPath()); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("a config was written although the key could not be stored: %v", statErr)
	}
	if len(run.hooks) != 0 || run.autostart != "" || len(run.started) != 0 {
		t.Errorf("the run went on: hooks %v, autostart %q, started %q", run.hooks, run.autostart, run.started)
	}
}

// A step that fails after the run began to write takes back what was written,
// so a failed setup leaves no half-installed agent.
func TestRunWindowsTakesBackWhatItWroteWhenALaterStepFails(t *testing.T) {
	for _, step := range []string{"hooks", "autostart", "start"} {
		t.Run(step, func(t *testing.T) {
			h := newHarnessOnAnyOS(t)
			run := newWindowsRun(t, h)
			run.failAt = step
			allowLoopback(t)
			server := pingServer(t, "tok")
			if err := Run(context.Background(), h.options("tok", server)); err == nil {
				t.Fatal("Run() = nil, want the step's failure")
			}
			if len(run.stored) != 0 {
				t.Errorf("the key is still stored: %v", run.stored)
			}
			if _, err := os.Stat(managedconfig.LegacyUserPath()); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the config is still there: %v", err)
			}
			if run.autostart != "" {
				t.Errorf("autostart is still set: %q", run.autostart)
			}
			if step != "hooks" && run.hooksGone != 1 {
				t.Errorf("the hooks were removed %d times, want once", run.hooksGone)
			}
		})
	}
}

func TestRunWindowsNeedsTheDaemonBesideTheCLI(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	if err := os.Remove(run.daemon); err != nil {
		t.Fatal(err)
	}
	server := pingServer(t, "tok")
	if err := Run(context.Background(), h.options("tok", server)); err == nil || !strings.Contains(err.Error(), windowsDaemonName) {
		t.Fatalf("Run() = %v, want it to name the missing %s", err, windowsDaemonName)
	}
}

// A setup over an existing install that fails part way leaves that install
// as it was: nothing of it is taken back.
func TestRunWindowsLeavesAnExistingInstallWhenARerunFails(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	server := pingServer(t, "tok")
	if err := Run(context.Background(), h.options("tok", server)); err != nil {
		t.Fatalf("first Run() = %v", err)
	}
	run.failAt = "autostart"
	if err := Run(context.Background(), h.options("tok", server)); err == nil {
		t.Fatal("second Run() = nil, want the step's failure")
	}
	if run.stored[WindowsCredentialName] != "tok" {
		t.Errorf("the key was taken away: %v", run.stored)
	}
	if _, err := os.Stat(managedconfig.LegacyUserPath()); err != nil {
		t.Errorf("the config was taken away: %v", err)
	}
	if run.autostart != run.daemon {
		t.Errorf("the sign-in entry was taken away: %q", run.autostart)
	}
	if run.hooksGone != 0 {
		t.Errorf("the hooks were removed %d times", run.hooksGone)
	}
}

// A daemon that is slow to answer keeps what setup wrote for it.
func TestRunWindowsKeepsTheInstallWhenTheDaemonIsSlow(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	overrideVar(t, &dialSocket, func(string, time.Duration) error { return errors.New("not listening yet") })
	overrideVar(t, &daemonStartWait, time.Millisecond)
	server := pingServer(t, "tok")
	err := Run(context.Background(), h.options("tok", server))
	if err == nil || !strings.Contains(err.Error(), "has not answered yet") {
		t.Fatalf("Run() = %v, want it to say the agent has not answered yet", err)
	}
	if run.stored[WindowsCredentialName] != "tok" || run.autostart != run.daemon || run.hooksGone != 0 {
		t.Errorf("the install was taken back: key %v, autostart %q, hooks removed %d", run.stored, run.autostart, run.hooksGone)
	}
	if _, err := os.Stat(managedconfig.LegacyUserPath()); err != nil {
		t.Errorf("the config was taken away: %v", err)
	}
}

// The old daemon holds the old key and the socket, so a setup over an
// existing install ends it before it starts the new one. A first install has
// none to end.
func TestRunWindowsRestartsTheDaemonOnARerun(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	server := pingServer(t, "tok")
	if err := Run(context.Background(), h.options("tok", server)); err != nil {
		t.Fatalf("first Run() = %v", err)
	}
	if run.stops != 0 {
		t.Fatalf("a first install stopped a daemon %d times", run.stops)
	}
	run.started = nil
	if err := Run(context.Background(), h.options("tok", server)); err != nil {
		t.Fatalf("second Run() = %v", err)
	}
	if run.stops != 1 || len(run.started) == 0 {
		t.Fatalf("on the re-run the daemon was stopped %d times and started %q, want one stop and a start", run.stops, run.started)
	}
}

func TestUninstallWindowsTakesBackWhatSetupWrote(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	server := pingServer(t, "tok")
	opts := h.options("tok", server)
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	identity, err := os.ReadFile(installation.LegacyUserPath())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	opts.Stdout = &out
	if err := Uninstall(context.Background(), opts); err != nil {
		t.Fatalf("Uninstall() = %v\n%s", err, out.String())
	}
	if len(run.stored) != 0 {
		t.Errorf("the key is still stored: %v", run.stored)
	}
	if _, err := os.Stat(managedconfig.LegacyUserPath()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the config is still there: %v", err)
	}
	if run.stoppedProgram != "" {
		t.Errorf("alone on the machine, uninstall limited its stop to %q, want whichever daemon serves the user", run.stoppedProgram)
	}
	if !strings.Contains(out.String(), "✓ Background agent stopped") {
		t.Errorf("uninstall ended the daemon and did not say so:\n%s", out.String())
	}
	if run.autostart != "" || run.hooksGone != 1 || run.stops != 1 {
		t.Errorf("autostart %q, hooks removed %d times, daemon stopped %d times; want none, 1, 1", run.autostart, run.hooksGone, run.stops)
	}
	if kept, err := os.ReadFile(installation.LegacyUserPath()); err != nil || string(kept) != string(identity) {
		t.Errorf("the installation identity was not kept as it was: %v", err)
	}
	// A second uninstall finds nothing and still succeeds.
	if err := Uninstall(context.Background(), opts); err != nil {
		t.Fatalf("second Uninstall() = %v", err)
	}
	if run.stops != 1 {
		t.Errorf("an uninstall without a user install stopped a daemon (%d stops)", run.stops)
	}
}

// A session without a credential store can't remove the key. Uninstall says
// so and takes nothing else away.
func TestUninstallWindowsStopsBeforeAnythingWhenTheSessionHasNoStore(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	server := pingServer(t, "tok")
	opts := h.options("tok", server)
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	run.delError = credstore.ErrNoLogonSession
	err := Uninstall(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "desktop session") {
		t.Fatalf("Uninstall() = %v, want it to send the user to a desktop session", err)
	}
	if run.autostart != run.daemon || run.hooksGone != 0 || run.stops != 0 {
		t.Errorf("uninstall went on: autostart %q, hooks removed %d, stops %d", run.autostart, run.hooksGone, run.stops)
	}
	if _, err := os.Stat(managedconfig.LegacyUserPath()); err != nil {
		t.Errorf("the config was removed: %v", err)
	}
}

// A setup with a new key that fails over an existing install puts the old
// key back: the running daemon was started with it, and the next sign-in
// must not pick up a key from a setup that failed.
func TestRunWindowsPutsTheOldKeyBackWhenARerunWithANewKeyFails(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	server := pingServerForKeys(t, "old-key", "new-key")
	if err := Run(context.Background(), h.options("old-key", server)); err != nil {
		t.Fatalf("first Run() = %v", err)
	}
	before, err := os.ReadFile(managedconfig.LegacyUserPath())
	if err != nil {
		t.Fatal(err)
	}
	run.failAt = "autostart"
	if err := Run(context.Background(), h.options("new-key", server)); err == nil {
		t.Fatal("second Run() = nil, want the step's failure")
	}
	if got := run.stored[WindowsCredentialName]; got != "old-key" {
		t.Fatalf("stored key = %q, want the old key back", got)
	}
	if after, err := os.ReadFile(managedconfig.LegacyUserPath()); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("the config was not put back with the key (%v):\n%s\nwant\n%s", err, after, before)
	}
	if run.stops != 0 {
		t.Errorf("the running daemon was stopped %d times by a setup that failed", run.stops)
	}
}

// A setup with a new key over an existing install keeps the new key when it
// succeeds, and also when it fails after the old daemon was stopped: the
// daemon this run starts, or the next one, has to find it.
func TestRunWindowsKeepsTheNewKeyOnceTheOldDaemonIsStopped(t *testing.T) {
	for _, failAt := range []string{"", "start"} {
		t.Run("fails at "+failAt, func(t *testing.T) {
			h := newHarnessOnAnyOS(t)
			run := newWindowsRun(t, h)
			allowLoopback(t)
			server := pingServerForKeys(t, "old-key", "new-key")
			if err := Run(context.Background(), h.options("old-key", server)); err != nil {
				t.Fatalf("first Run() = %v", err)
			}
			run.failAt = failAt
			err := Run(context.Background(), h.options("new-key", server))
			if (err != nil) != (failAt != "") {
				t.Fatalf("second Run() = %v with failAt %q", err, failAt)
			}
			if got := run.stored[WindowsCredentialName]; got != "new-key" {
				t.Fatalf("stored key = %q, want the new key", got)
			}
			if run.stops != 1 {
				t.Fatalf("the old daemon was stopped %d times, want once", run.stops)
			}
		})
	}
}

// Claude Code runs no hooks with disableAllHooks set, and the installer
// keeps that setting: setup says so, as it does on macOS.
func TestRunWindowsWarnsWhenClaudeCodeHasAllHooksDisabled(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	newWindowsRun(t, h)
	allowLoopback(t)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	settings := filepath.Join(h.home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"disableAllHooks": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), h.options("tok", pingServer(t, "tok"))); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if !strings.Contains(h.errOut.String(), "warning: disableAllHooks in "+settings) {
		t.Fatalf("setup did not warn about disableAllHooks:\n%s", h.errOut.String())
	}
}

// pingServerForKeys is one server that knows several keys, for a second
// setup with a new key: a new key for the same server.
func pingServerForKeys(t *testing.T, keys ...string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/authorization-ledger/ping" {
			http.NotFound(w, r)
			return
		}
		if !slices.Contains(keys, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"organization_id": "org_test", "organization_name": "Acme"})
	}))
	t.Cleanup(server.Close)
	return server
}

// One install per user keeps one set of records. A setup for another server
// over an install is refused before that server is asked anything and before
// anything is written: the key, the config and the running daemon stay.
func TestRunWindowsRefusesAnotherServerOverAnInstall(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	if err := Run(context.Background(), h.options("old-key", pingServer(t, "old-key"))); err != nil {
		t.Fatalf("first Run() = %v", err)
	}
	before, err := os.ReadFile(managedconfig.LegacyUserPath())
	if err != nil {
		t.Fatal(err)
	}
	asked := 0
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { asked++ }))
	t.Cleanup(other.Close)
	err = Run(context.Background(), h.options("new-key", other))
	if err == nil || !strings.Contains(err.Error(), "kontext setup --uninstall") {
		t.Fatalf("Run() for another server = %v, want a refusal that names the way out", err)
	}
	if asked != 0 {
		t.Errorf("the other server was asked %d times by a setup that was refused", asked)
	}
	if got := run.stored[WindowsCredentialName]; got != "old-key" {
		t.Errorf("stored key = %q, want the old key", got)
	}
	if after, err := os.ReadFile(managedconfig.LegacyUserPath()); err != nil || !bytes.Equal(after, before) {
		t.Errorf("the config changed (%v)", err)
	}
	if run.stops != 0 {
		t.Errorf("the running daemon was stopped %d times", run.stops)
	}
	// After an uninstall the PC is free for the other server.
	if err := Uninstall(context.Background(), h.options("old-key", other)); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
	if err := Run(context.Background(), h.options("new-key", pingServer(t, "new-key"))); err != nil {
		t.Fatalf("Run() after the uninstall = %v", err)
	}
}

// The same server spelled another way is not another server: a new key for
// it goes in without an uninstall.
func TestRunWindowsTakesANewKeyForTheSameServerSpelledAnotherWay(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	server := pingServerForKeys(t, "old-key", "new-key")
	first := h.options("old-key", server)
	first.CloudURL += "/"
	if err := Run(context.Background(), first); err != nil {
		t.Fatalf("first Run() = %v", err)
	}
	if err := Run(context.Background(), h.options("new-key", server)); err != nil {
		t.Fatalf("Run() with the URL spelled without its slash = %v", err)
	}
	if got := run.stored[WindowsCredentialName]; got != "new-key" {
		t.Errorf("stored key = %q, want the new key", got)
	}
}

func TestSameServer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"https://api.example.com", "https://api.example.com", true},
		{"https://api.example.com/", "https://api.example.com", true},
		{"https://API.Example.com", "https://api.example.com", true},
		{"https://api.example.com:443", "https://api.example.com", true},
		{"http://127.0.0.1:80", "http://127.0.0.1/", true},
		{"https://api.example.com", "https://staging.example.com", false},
		{"https://api.example.com:8443", "https://api.example.com", false},
		{"http://127.0.0.1:8080", "https://127.0.0.1:8080", false},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8081", false},
	} {
		if got := sameServer(tc.a, tc.b); got != tc.want {
			t.Errorf("sameServer(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if got := sameServer(tc.b, tc.a); got != tc.want {
			t.Errorf("sameServer(%q, %q) = %v, want %v", tc.b, tc.a, got, tc.want)
		}
	}
}

// Beside a machine-wide install, uninstall ends only the daemon its own
// sign-in entry names, and none when there is no entry to tell them apart.
// It says "stopped" only when it ended one.
func TestUninstallWindowsBesideAMachineWideInstallEndsOnlyItsOwnDaemon(t *testing.T) {
	for _, tc := range []struct {
		name        string
		dropEntry   bool
		daemonGone  bool
		wantProgram string
		wantStops   int
		wantSaid    bool
	}{
		{name: "its entry names the daemon", wantStops: 1, wantSaid: true},
		{name: "the daemon is not running", daemonGone: true, wantStops: 1},
		{name: "no entry", dropEntry: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarnessOnAnyOS(t)
			run := newWindowsRun(t, h)
			allowLoopback(t)
			opts := h.options("tok", pingServer(t, "tok"))
			if err := Run(context.Background(), opts); err != nil {
				t.Fatalf("Run() = %v", err)
			}
			// A machine-wide install arrives after the user's own.
			if err := os.MkdirAll(filepath.Dir(systemConfigPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(systemConfigPath, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
			want := run.daemon
			if tc.dropEntry {
				run.autostart, want = "", ""
			}
			if tc.daemonGone {
				run.started = nil
			}
			var out bytes.Buffer
			opts.Stdout, opts.Stderr = &out, &out
			if err := Uninstall(context.Background(), opts); err != nil {
				t.Fatalf("Uninstall() = %v\n%s", err, out.String())
			}
			if run.stops != tc.wantStops || (tc.wantStops > 0 && run.stoppedProgram != want) {
				t.Errorf("stops = %d limited to %q, want %d limited to %q", run.stops, run.stoppedProgram, tc.wantStops, want)
			}
			if said := strings.Contains(out.String(), "Background agent stopped"); said != tc.wantSaid {
				t.Errorf("said stopped: %v, want %v:\n%s", said, tc.wantSaid, out.String())
			}
		})
	}
}

// Beside a machine-wide install the sign-in entry is what tells this
// install's daemon from that one's. An uninstall whose stop fails puts the
// entry back, so that the next uninstall can still find the daemon, and
// takes nothing further away.
func TestUninstallWindowsPutsTheEntryBackWhenTheStopFails(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	opts := h.options("tok", pingServer(t, "tok"))
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(systemConfigPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(systemConfigPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	run.stopError = errors.New("the process would not end")
	if err := Uninstall(context.Background(), opts); err == nil {
		t.Fatal("Uninstall() = nil, want the stop's failure")
	}
	if run.autostart != run.daemon {
		t.Errorf("the sign-in entry is %q after a failed stop, want it back as %q", run.autostart, run.daemon)
	}
	if _, err := os.Stat(managedconfig.LegacyUserPath()); err != nil {
		t.Errorf("the config was removed although the daemon still runs: %v", err)
	}
	// The next uninstall finds the daemon by the entry again.
	run.stopError = nil
	if err := Uninstall(context.Background(), opts); err != nil {
		t.Fatalf("second Uninstall() = %v", err)
	}
	if run.stoppedProgram != run.daemon || run.autostart != "" {
		t.Errorf("second uninstall: stop limited to %q, entry %q; want the stop limited to %q and no entry", run.stoppedProgram, run.autostart, run.daemon)
	}
}

// A machine-wide config that cannot be looked at may well be there: the stop
// stays limited to this install's own program. Only one that does not exist
// makes this install the only one.
func TestStopOwnDaemonTreatsAnUnreadableMachineConfigAsPresent(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	blocker := filepath.Join(t.TempDir(), "not-a-folder")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	overrideVar(t, &systemConfigPath, filepath.Join(blocker, "managed.json"))
	if _, err := os.Lstat(systemConfigPath); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Skipf("this OS reports a path below a file as %v, so the case cannot be made here", err)
	}
	if _, err := stopOwnDaemon(autostart.Command(run.daemon)); err != nil {
		t.Fatal(err)
	}
	if run.stoppedProgram != run.daemon {
		t.Fatalf("the stop was limited to %q, want this install's program %q", run.stoppedProgram, run.daemon)
	}
	run.stops = 0
	if stopped, err := stopOwnDaemon(""); err != nil || stopped || run.stops != 0 {
		t.Fatalf("with no entry: stopped %v, %d stops, %v; want nothing stopped", stopped, run.stops, err)
	}
}

// reportClaudeHooks answers as the hook installer does: one result for
// Claude Code's user file and one for an agent it skips on Windows.
func reportClaudeHooks(opts hookinstall.Options, action string) {
	if opts.Report == nil {
		return
	}
	opts.Report(hookinstall.Result{File: hookinstall.File{Kind: "claude-user", Path: `C:\Users\someone\.claude\settings.json`}, Action: action})
	opts.Report(hookinstall.Result{File: hookinstall.File{Kind: "codex", Path: `C:\Users\someone\.codex\hooks.json`}, Action: "skip", Reason: "unsupported-on-windows"})
}

// Setup and uninstall say what they did to Claude Code's hooks in one line
// of their own, and do not print the hook installer's plan.
func TestWindowsSetupAndUninstallSpeakOfTheHooksInTheirOwnWords(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	opts := h.options("tok", pingServer(t, "tok"))
	var out bytes.Buffer
	opts.Stdout = &out
	if err := Run(context.Background(), opts); err != nil {
		t.Fatalf("Run() = %v", err)
	}
	if len(run.hooks) != 1 || run.hooks[0].Out != nil {
		t.Fatalf("setup handed the hook installer an output to print its plan to: %+v", run.hooks)
	}
	if !strings.Contains(out.String(), "✓ Claude Code hooks installed (") || strings.Contains(out.String(), "unsupported-on-windows") || strings.Contains(out.String(), ".codex") {
		t.Fatalf("setup's output about the hooks:\n%s", out.String())
	}

	out.Reset()
	if err := Uninstall(context.Background(), opts); err != nil {
		t.Fatalf("Uninstall() = %v", err)
	}
	for _, want := range []string{"✓ Claude Code hooks removed (", "✓ Background agent no longer starts at sign-in", "✓ Config removed: "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("uninstall's output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "unsupported-on-windows") {
		t.Errorf("uninstall printed the hook installer's plan:\n%s", out.String())
	}

	// With nothing of its own left, uninstall claims no removal.
	out.Reset()
	if err := Uninstall(context.Background(), opts); err != nil {
		t.Fatalf("second Uninstall() = %v", err)
	}
	for _, claim := range []string{"hooks removed", "no longer starts", "Config removed", "Install key removed", "Background agent stopped"} {
		if strings.Contains(out.String(), claim) {
			t.Errorf("an uninstall with nothing to remove says %q:\n%s", claim, out.String())
		}
	}
}

// A first install that fails takes the hooks back without saying a second
// time that they were installed.
func TestRunWindowsUndoDoesNotClaimTheHooksWereInstalled(t *testing.T) {
	h := newHarnessOnAnyOS(t)
	run := newWindowsRun(t, h)
	allowLoopback(t)
	opts := h.options("tok", pingServer(t, "tok"))
	var out bytes.Buffer
	opts.Stdout = &out
	run.failAt = "autostart"
	if err := Run(context.Background(), opts); err == nil {
		t.Fatal("Run() = nil, want the step's failure")
	}
	if got := strings.Count(out.String(), "Claude Code hooks installed"); got != 1 {
		t.Fatalf("setup said the hooks were installed %d times, want once:\n%s", got, out.String())
	}
	if run.hooksGone != 1 {
		t.Fatalf("the hooks were taken back %d times, want once", run.hooksGone)
	}
}
