package managedobserve

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/buildinfo"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/managedconfig"
)

// Ways the updater can fail: run where it must not (organization config,
// Linux, opted out, a development build), misread the package (cask vs formula,
// version, prefix), stop on a broken unrelated tap, report a change that did
// not happen, check on a timer that sleep or restarts reset, or upgrade a
// homebrew-core install, which Homebrew does not allow.

func TestHomebrewUpdaterInstall(t *testing.T) {
	for _, tc := range []struct {
		name, goos, resolved, optOut string
		scope                        managedconfig.Scope
		brew                         bool
		want                         homebrewInstall
	}{
		{name: "cask", goos: "darwin", scope: managedconfig.ScopeUser, brew: true, resolved: "/opt/homebrew/Caskroom/kontext/1.12.0/kontext",
			want: homebrewInstall{brewPath: "/opt/homebrew/bin/brew", kind: "--cask", version: "1.12.0", link: "/opt/homebrew/bin/kontext"}},
		{name: "tap formula on Intel", goos: "darwin", scope: managedconfig.ScopeUser, brew: true, resolved: "/usr/local/Cellar/kontext/1.2.3/bin/kontext",
			want: homebrewInstall{brewPath: "/usr/local/bin/brew", kind: "--formula", version: "1.2.3", link: "/usr/local/bin/kontext"}},
		{name: "custom prefix", goos: "darwin", scope: managedconfig.ScopeUser, brew: true, resolved: "/tmp/hb/Caskroom/kontext/2.0.0/kontext"},
		{name: "organization config", goos: "darwin", scope: managedconfig.ScopeSystem, brew: true, resolved: "/opt/homebrew/Caskroom/kontext/1.12.0/kontext"},
		{name: "linux", goos: "linux", scope: managedconfig.ScopeUser, brew: true, resolved: "/opt/homebrew/Caskroom/kontext/1.12.0/kontext"},
		{name: "opted out", goos: "darwin", scope: managedconfig.ScopeUser, brew: true, optOut: "1", resolved: "/opt/homebrew/Caskroom/kontext/1.12.0/kontext"},
		{name: "development build", goos: "darwin", scope: managedconfig.ScopeUser, brew: true, resolved: "/Users/dev/Library/Application Support/KontextManagement/runtime/builds/x/kontext"},
		{name: "brew missing", goos: "darwin", scope: managedconfig.ScopeUser, resolved: "/opt/homebrew/Caskroom/kontext/1.12.0/kontext"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetUpdaterSeams(t)
			runtimeGOOS = tc.goos
			t.Setenv(envNoUpdateCheck, tc.optOut)
			executablePath = func() (string, error) { return "/opt/homebrew/bin/kontext", nil }
			evalSymlinksPath = func(string) (string, error) { return tc.resolved, nil }
			statPath = func(path string) (os.FileInfo, error) {
				if tc.brew && strings.HasSuffix(path, "/bin/brew") {
					return fakeFileInfo{name: "brew"}, nil
				}
				return nil, os.ErrNotExist
			}
			runCommand = func(context.Context, []string, string, ...string) (string, error) {
				t.Fatal("eligibility must not run brew")
				return "", nil
			}
			got, ok := homebrewUpdaterInstall(managedconfig.LoadedConfig{Scope: tc.scope}, diagnostic.Logger{})
			if got != tc.want || ok != (tc.want != homebrewInstall{}) {
				t.Fatalf("homebrewUpdaterInstall() = %+v, %v; want %+v", got, ok, tc.want)
			}
		})
	}
}

func TestCheckHomebrewUpgrade(t *testing.T) {
	cask := homebrewInstall{brewPath: "/opt/homebrew/bin/brew", kind: "--cask", version: "1.12.0", link: "/opt/homebrew/bin/kontext"}
	for _, tc := range []struct {
		name                 string
		updateErr, upErr     error
		untrusted, probeErr  bool
		after                string
		wantChanged, wantErr bool
	}{
		{name: "new version", after: "/opt/homebrew/Caskroom/kontext/1.17.0/kontext", wantChanged: true},
		{name: "already current", after: "/opt/homebrew/Caskroom/kontext/1.12.0/kontext"},
		{name: "broken unrelated tap", updateErr: errors.New("Fetching broken/tap failed"), after: "/opt/homebrew/Caskroom/kontext/1.17.0/kontext", wantChanged: true},
		{name: "upgrade fails", upErr: errors.New("download failed"), wantErr: true},
		// Offline after wake: a stale tap shows nothing new, so the check fails and retries within the hour.
		{name: "refresh fails, nothing to upgrade", updateErr: errors.New("could not resolve host"), after: "/opt/homebrew/Caskroom/kontext/1.12.0/kontext", wantErr: true},
		// Installed before Homebrew 7: brew upgrade would trust the cask itself, so the check stops.
		{name: "untrusted tap", untrusted: true, wantErr: true},
		// A probe that fails without an answer (timeout) must not fall through to the upgrade.
		{name: "trust check fails", probeErr: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetUpdaterSeams(t)
			var calls []string
			runCommand = func(ctx context.Context, env []string, _ string, args ...string) (string, error) {
				if _, ok := ctx.Deadline(); !ok {
					t.Fatalf("%v has no timeout", args)
				}
				calls = append(calls, strings.Join(env, " ")+" | "+strings.Join(args, " "))
				if args[0] == "info" && tc.untrusted {
					return "Error: Refusing to load cask kontext-security/tap/kontext from untrusted tap kontext-security/tap.", errors.New("exit status 1")
				}
				if args[0] == "info" && tc.probeErr {
					return "", context.DeadlineExceeded
				}
				if args[0] == "info" {
					return "{}", nil
				}
				if args[0] == "update-if-needed" {
					return "", tc.updateErr
				}
				return "", tc.upErr
			}
			evalSymlinksPath = func(string) (string, error) { return tc.after, nil }
			changed, notice, err := checkHomebrewUpgrade(context.Background(), cask, diagnostic.Logger{})
			if changed != tc.wantChanged || (err != nil) != tc.wantErr || (notice != "") != (tc.updateErr != nil && !tc.wantErr) {
				t.Fatalf("checkHomebrewUpgrade() = %v, %q, %v", changed, notice, err)
			}
			want := []string{
				"HOMEBREW_AUTO_UPDATE_SECS=" + brewAutoUpdateSecs + " | update-if-needed",
				" | info --json=v2 --cask " + homebrewFormula,
				"HOMEBREW_NO_AUTO_UPDATE=1 | upgrade --cask --no-ask " + homebrewFormula,
			}
			if tc.untrusted || tc.probeErr {
				want = want[:2]
			}
			if tc.untrusted {
				if err == nil || !strings.Contains(err.Error(), "Run: brew trust --cask "+homebrewFormula) {
					t.Fatalf("error = %v, want the brew trust command", err)
				}
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("commands = %q, want %q", calls, want)
			}
		})
	}
}

func TestUpdateScheduleUsesTheSavedCheckTime(t *testing.T) {
	resetUpdaterSeams(t)
	state := filepath.Join(t.TempDir(), "update-check.json")
	updateStatePath = func() string { return state }
	firstUpdateCheckDelay, updateWakeInterval = time.Millisecond, time.Millisecond
	t.Cleanup(func() { firstUpdateCheckDelay, updateWakeInterval = 2*time.Minute, 10*time.Minute })

	// A check five hours ago, then a restart: not due yet under a six-hour interval.
	if err := writeJSONBreadcrumb(state, UpdateState{CheckedAt: time.Now().Add(-5 * time.Hour), Source: "cask"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	runUpdateSchedule(ctx, "cask", 6*time.Hour, func(context.Context) (bool, string, error) {
		t.Fatal("checked before the interval elapsed")
		return false, "", nil
	}, diagnostic.Logger{}, make(chan struct{}, 1))

	// A check time ahead of the clock does not hold checks back forever.
	if err := writeJSONBreadcrumb(state, UpdateState{CheckedAt: time.Now().Add(48 * time.Hour), Source: "cask"}); err != nil {
		t.Fatal(err)
	}
	ahead := make(chan struct{}, 1)
	runUpdateSchedule(context.Background(), "cask", 6*time.Hour, func(context.Context) (bool, string, error) {
		return true, "", nil
	}, diagnostic.Logger{}, ahead)
	if len(ahead) != 1 {
		t.Fatal("a future check time blocked the check")
	}

	// A failed check an hour and a half ago is due again, though six hours have not passed.
	if err := writeJSONBreadcrumb(state, UpdateState{CheckedAt: time.Now().Add(-90 * time.Minute), Source: "cask", Error: "brew upgrade: lock held"}); err != nil {
		t.Fatal(err)
	}
	retried := make(chan struct{}, 1)
	runUpdateSchedule(context.Background(), "cask", 6*time.Hour, func(context.Context) (bool, string, error) {
		return true, "", nil
	}, diagnostic.Logger{}, retried)
	if len(retried) != 1 {
		t.Fatal("a failed check was not retried within the hour")
	}

	// A recent check by the homebrew-core formula before a switch to the cask
	// does not hold the cask's first check back; an upgrade ends the schedule.
	if err := writeJSONBreadcrumb(state, UpdateState{CheckedAt: time.Now().Add(-time.Minute), Source: "homebrew-core"}); err != nil {
		t.Fatal(err)
	}
	upgraded := make(chan struct{}, 1)
	runUpdateSchedule(context.Background(), "cask", 6*time.Hour, func(context.Context) (bool, string, error) {
		return true, "", nil
	}, diagnostic.Logger{}, upgraded)
	select {
	case <-upgraded:
	default:
		t.Fatal("upgrade was not signaled")
	}
	saved, err := LoadUpdateState()
	if err != nil || time.Since(saved.CheckedAt) > time.Minute || saved.Source != "cask" {
		t.Fatalf("saved state = %+v, %v", saved, err)
	}

	// A check time that cannot be saved still holds the next check back.
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	updateStatePath = func() string { return filepath.Join(blocker, "update-check.json") }
	checks := 0
	unsaved, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	runUpdateSchedule(unsaved, "cask", 6*time.Hour, func(context.Context) (bool, string, error) {
		checks++
		return false, "", nil
	}, diagnostic.Logger{}, make(chan struct{}, 1))
	if checks != 1 {
		t.Fatalf("ran %d checks while the check time could not be saved, want 1", checks)
	}
}

func TestHomebrewCoreNeverUpgrades(t *testing.T) {
	stubHomebrewBuild(t)
	state := filepath.Join(t.TempDir(), "update-check.json")
	updateStatePath = func() string { return state }
	firstUpdateCheckDelay = time.Millisecond
	t.Cleanup(func() { firstUpdateCheckDelay = 2 * time.Minute })
	checked := make(chan []string, 4)
	runCommand = func(_ context.Context, _ []string, _ string, args ...string) (string, error) {
		checked <- args
		if args[0] != "outdated" && args[0] != "update-if-needed" {
			t.Errorf("homebrew-core build ran brew %v", args)
		}
		return `{"formulae":[{"name":"kontext","installed_versions":["1.2.3"],"current_version":"1.2.4"}]}`, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upgraded := startHomebrewUpdater(ctx, managedconfig.LoadedConfig{Scope: managedconfig.ScopeUser}, diagnostic.Logger{})
	for _, want := range []string{"update-if-needed", "outdated"} {
		select {
		case args := <-checked:
			if args[0] != want {
				t.Fatalf("brew call = %v, want %s", args, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no %s call", want)
		}
	}
	cancel()
	select {
	case <-upgraded:
		t.Fatal("homebrew-core build signaled an upgrade")
	case <-time.After(20 * time.Millisecond):
	}
}

func TestDaemonUpdateIntervalFromEnv(t *testing.T) {
	t.Setenv(envDaemonUpdateInterval, "25ms")
	if got := daemonUpdateInterval(); got != 25*time.Millisecond {
		t.Fatalf("daemonUpdateInterval() = %s, want 25ms", got)
	}
	t.Setenv(envDaemonUpdateInterval, "not-a-duration")
	if got := daemonUpdateInterval(); got != defaultDaemonUpdateInterval {
		t.Fatalf("daemonUpdateInterval(invalid) = %s, want %s", got, defaultDaemonUpdateInterval)
	}
}

func TestHomebrewOutdatedWarning(t *testing.T) {
	for name, test := range map[string]struct {
		output  string
		err     error
		want    string
		wantErr bool
	}{
		"outdated":        {output: `{"formulae":[{"name":"kontext","installed_versions":["1.2.3"],"current_version":"1.2.4"}],"casks":[]}`, want: "kontext 1.2.3 is outdated; 1.2.4 is available. Run: brew upgrade kontext"},
		"up to date":      {output: `{"formulae":[],"casks":[]}`},
		"brew error":      {err: errors.New("brew failed"), wantErr: true},
		"invalid JSON":    {output: "not JSON", wantErr: true},
		"missing version": {output: `{"formulae":[{"name":"kontext"}]}`, wantErr: true},
		"other formula":   {output: `{"formulae":[{"name":"other","installed_versions":["1"],"current_version":"2"}]}`},
	} {
		t.Run(name, func(t *testing.T) {
			resetUpdaterSeams(t)
			runCommand = func(ctx context.Context, _ []string, _ string, args ...string) (string, error) {
				if !reflect.DeepEqual(args, []string{"outdated", "--formula", "--json=v2", "kontext"}) {
					t.Fatalf("command = %v", args)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("brew outdated has no timeout")
				}
				return test.output, test.err
			}
			warning, err := homebrewOutdatedWarning(context.Background(), "/opt/homebrew/bin/brew")
			if warning != test.want || (err != nil) != test.wantErr {
				t.Fatalf("homebrewOutdatedWarning() = %q, %v, want %q, error %v", warning, err, test.want, test.wantErr)
			}
		})
	}
}

func resetUpdaterSeams(t *testing.T) {
	t.Helper()
	runtimeGOOS = runtime.GOOS
	executablePath = os.Executable
	evalSymlinksPath = filepath.EvalSymlinks
	statPath = os.Stat
	runCommand = runCommandOutput
	homebrewBuild = buildinfo.HomebrewBuild
	statePath := updateStatePath
	t.Cleanup(func() {
		updateStatePath = statePath
		runtimeGOOS = runtime.GOOS
		executablePath = os.Executable
		evalSymlinksPath = filepath.EvalSymlinks
		statPath = os.Stat
		runCommand = runCommandOutput
		homebrewBuild = buildinfo.HomebrewBuild
	})
}

func stubHomebrewBuild(t *testing.T) {
	t.Helper()
	resetUpdaterSeams(t)
	homebrewBuild = func() bool { return true }
	runtimeGOOS = "darwin"
	executablePath = func() (string, error) { return "/opt/homebrew/bin/kontext", nil }
	evalSymlinksPath = func(string) (string, error) {
		return "/opt/homebrew/Cellar/kontext/1.2.3/bin/kontext", nil
	}
	statPath = func(string) (os.FileInfo, error) { return fakeFileInfo{name: "brew"}, nil }
	t.Setenv(envNoUpdateCheck, "")
}

type fakeFileInfo struct {
	name string
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() os.FileMode  { return 0o755 }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

type channelWriter struct {
	ch chan<- string
}

func (w channelWriter) Write(p []byte) (int, error) {
	select {
	case w.ch <- string(p):
	default:
	}
	return len(p), nil
}

// A homebrew-core check on a tap it could not refresh saves an error, not a clean result.
func TestHomebrewCoreRefreshFailureIsSaved(t *testing.T) {
	stubHomebrewBuild(t)
	state := filepath.Join(t.TempDir(), "update-check.json")
	updateStatePath = func() string { return state }
	firstUpdateCheckDelay = time.Millisecond
	t.Cleanup(func() { firstUpdateCheckDelay = 2 * time.Minute })
	runCommand = func(_ context.Context, _ []string, _ string, args ...string) (string, error) {
		if args[0] == "update-if-needed" {
			return "", errors.New("could not resolve host")
		}
		return `{"formulae":[]}`, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startHomebrewUpdater(ctx, managedconfig.LoadedConfig{Scope: managedconfig.ScopeUser}, diagnostic.Logger{})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if saved, err := LoadUpdateState(); err == nil {
			if !strings.Contains(saved.Error, "update-if-needed") {
				t.Fatalf("saved state = %+v, want the refresh failure", saved)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no check saved")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
