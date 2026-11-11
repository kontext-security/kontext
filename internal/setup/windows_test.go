package setup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	delError   error
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
	overrideVar(t, &stopWindowsDaemon, func() error { run.stops++; return nil })
	overrideVar(t, &installWindowsHooks, func(opts hookinstall.Options) error {
		if run.failAt == "hooks" {
			return errors.New("hooks failed")
		}
		run.hooks = append(run.hooks, opts)
		return nil
	})
	overrideVar(t, &removeWindowsHooks, func(hookinstall.Options) error { run.hooksGone++; return nil })
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
