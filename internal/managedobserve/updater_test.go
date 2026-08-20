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

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/managedconfig"
)

func TestHomebrewUpdaterEligibility(t *testing.T) {
	tests := []struct {
		name         string
		goos         string
		scope        managedconfig.Scope
		exe          string
		optBrew      bool
		intelBrew    bool
		listErr      error
		noUpdate     string
		want         bool
		wantBrewPath string
	}{
		{
			name:         "user scope brew install enables updater",
			goos:         "darwin",
			scope:        managedconfig.ScopeUser,
			exe:          "/opt/homebrew/Cellar/kontext/1.2.3/bin/kontext",
			optBrew:      true,
			want:         true,
			wantBrewPath: "/opt/homebrew/bin/brew",
		},
		{
			name:         "intel brew install uses matching brew path",
			goos:         "darwin",
			scope:        managedconfig.ScopeUser,
			exe:          "/usr/local/Cellar/kontext/1.2.3/bin/kontext",
			optBrew:      true,
			intelBrew:    true,
			want:         true,
			wantBrewPath: "/usr/local/bin/brew",
		},
		{
			name:      "system scope skips updater",
			goos:      "darwin",
			scope:     managedconfig.ScopeSystem,
			exe:       "/opt/homebrew/Cellar/kontext/1.2.3/bin/kontext",
			optBrew:   true,
			intelBrew: true,
			want:      false,
		},
		{
			name:    "non darwin skips updater",
			goos:    "linux",
			scope:   managedconfig.ScopeUser,
			exe:     "/opt/homebrew/Cellar/kontext/1.2.3/bin/kontext",
			optBrew: true,
			want:    false,
		},
		{
			name:  "missing brew skips updater",
			goos:  "darwin",
			scope: managedconfig.ScopeUser,
			exe:   "/opt/homebrew/Cellar/kontext/1.2.3/bin/kontext",
			want:  false,
		},
		{
			name:         "failed brew list skips updater",
			goos:         "darwin",
			scope:        managedconfig.ScopeUser,
			exe:          "/opt/homebrew/Cellar/kontext/1.2.3/bin/kontext",
			optBrew:      true,
			listErr:      errors.New("formula missing"),
			want:         false,
			wantBrewPath: "/opt/homebrew/bin/brew",
		},
		{
			name:     "no update check env skips updater",
			goos:     "darwin",
			scope:    managedconfig.ScopeUser,
			exe:      "/opt/homebrew/Cellar/kontext/1.2.3/bin/kontext",
			optBrew:  true,
			noUpdate: "1",
			want:     false,
		},
		{
			name:      "non brew executable skips updater",
			goos:      "darwin",
			scope:     managedconfig.ScopeUser,
			exe:       "/usr/local/bin/kontext",
			optBrew:   true,
			intelBrew: true,
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetUpdaterSeams(t)
			runtimeGOOS = tc.goos
			executablePath = func() (string, error) { return "/tmp/kontext", nil }
			evalSymlinksPath = func(string) (string, error) { return tc.exe, nil }
			statPath = func(path string) (os.FileInfo, error) {
				if tc.optBrew && path == "/opt/homebrew/bin/brew" {
					return fakeFileInfo{name: "brew"}, nil
				}
				if tc.intelBrew && path == "/usr/local/bin/brew" {
					return fakeFileInfo{name: "brew"}, nil
				}
				return nil, os.ErrNotExist
			}
			var gotBrewPath string
			runCommand = func(_ context.Context, path string, args ...string) (string, error) {
				if reflect.DeepEqual(args, []string{"list", "--versions", homebrewFormula}) {
					gotBrewPath = path
					if tc.listErr != nil {
						return "", tc.listErr
					}
					return "kontext-security/tap/kontext 1.2.3\n", nil
				}
				t.Fatalf("unexpected command args = %v", args)
				return "", nil
			}
			if tc.noUpdate != "" {
				t.Setenv(envNoUpdateCheck, tc.noUpdate)
			}

			_, got := homebrewUpdaterConfig(context.Background(), managedconfig.LoadedConfig{Scope: tc.scope}, diagnostic.Logger{})
			if got != tc.want {
				t.Fatalf("homebrewUpdaterConfig() ok = %v, want %v", got, tc.want)
			}
			if gotBrewPath != tc.wantBrewPath {
				t.Fatalf("brew path = %q, want %q", gotBrewPath, tc.wantBrewPath)
			}
		})
	}
}

func TestCheckHomebrewUpgradeNoVersionChange(t *testing.T) {
	resetUpdaterSeams(t)
	var calls [][]string
	runCommand = func(_ context.Context, _ string, args ...string) (string, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "list" {
			return "kontext-security/tap/kontext 1.2.3\n", nil
		}
		return "", nil
	}

	changed, err := checkHomebrewUpgrade(context.Background(), "/opt/homebrew/bin/brew")
	if err != nil {
		t.Fatalf("checkHomebrewUpgrade() error = %v", err)
	}
	if changed {
		t.Fatal("checkHomebrewUpgrade() changed = true, want false")
	}
	want := [][]string{
		{"list", "--versions", homebrewFormula},
		{"update-if-needed"},
		{"upgrade", "--formula", "--no-ask", homebrewFormula},
		{"list", "--versions", homebrewFormula},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("commands = %#v, want %#v", calls, want)
	}
}

func TestHomebrewUpdaterEligibilityHonorsCanceledContext(t *testing.T) {
	resetUpdaterSeams(t)
	runtimeGOOS = "darwin"
	executablePath = func() (string, error) { return "/tmp/kontext", nil }
	evalSymlinksPath = func(string) (string, error) {
		return "/opt/homebrew/Cellar/kontext/1.2.3/bin/kontext", nil
	}
	statPath = func(path string) (os.FileInfo, error) {
		if path == "/opt/homebrew/bin/brew" {
			return fakeFileInfo{name: "brew"}, nil
		}
		return nil, os.ErrNotExist
	}
	sawCanceledContext := false
	runCommand = func(ctx context.Context, _ string, args ...string) (string, error) {
		if !reflect.DeepEqual(args, []string{"list", "--versions", homebrewFormula}) {
			t.Fatalf("unexpected command args = %v", args)
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			sawCanceledContext = true
		}
		return "", ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, ok := homebrewUpdaterConfig(ctx, managedconfig.LoadedConfig{Scope: managedconfig.ScopeUser}, diagnostic.Logger{})
	if ok {
		t.Fatal("homebrewUpdaterConfig() ok = true, want false after cancellation")
	}
	if !sawCanceledContext {
		t.Fatal("brew list did not receive canceled daemon context")
	}
}

func TestCheckHomebrewUpgradeVersionChange(t *testing.T) {
	resetUpdaterSeams(t)
	listCalls := 0
	runCommand = func(_ context.Context, _ string, args ...string) (string, error) {
		if args[0] != "list" {
			return "", nil
		}
		listCalls++
		if listCalls == 1 {
			return "kontext-security/tap/kontext 1.2.3\n", nil
		}
		return "kontext-security/tap/kontext 1.2.4\n", nil
	}

	changed, err := checkHomebrewUpgrade(context.Background(), "/opt/homebrew/bin/brew")
	if err != nil {
		t.Fatalf("checkHomebrewUpgrade() error = %v", err)
	}
	if !changed {
		t.Fatal("checkHomebrewUpgrade() changed = false, want true")
	}
}

func TestRunHomebrewUpdaterLogsUpdateFailureAndKeepsRunning(t *testing.T) {
	resetUpdaterSeams(t)
	logs := make(chan string, 8)
	runCommand = func(_ context.Context, _ string, args ...string) (string, error) {
		if args[0] == "update-if-needed" {
			return "", errors.New("network down")
		}
		return "kontext-security/tap/kontext 1.2.3\n", nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	upgraded := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runHomebrewUpdater(ctx, homebrewUpdaterConfigValue{
			brewPath: "/opt/homebrew/bin/brew",
			interval: time.Millisecond,
		}, diagnostic.New(channelWriter{ch: logs}, true), upgraded)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for updater shutdown")
		}
	})

	deadline := time.After(time.Second)
	for {
		select {
		case line := <-logs:
			if !strings.Contains(line, "brew update-if-needed") {
				continue
			}
			select {
			case <-upgraded:
				t.Fatal("updater signaled upgrade after update failure")
			default:
			}
			return
		case <-deadline:
			t.Fatal("timed out waiting for updater failure log")
		}
	}
}

func TestCheckHomebrewUpgradeUpgradeFailure(t *testing.T) {
	resetUpdaterSeams(t)
	runCommand = func(_ context.Context, _ string, args ...string) (string, error) {
		if args[0] == "upgrade" {
			return "", errors.New("pinned formula")
		}
		return "kontext-security/tap/kontext 1.2.3\n", nil
	}

	changed, err := checkHomebrewUpgrade(context.Background(), "/opt/homebrew/bin/brew")
	if err == nil || !strings.Contains(err.Error(), "brew upgrade") {
		t.Fatalf("checkHomebrewUpgrade() error = %v, want brew upgrade error", err)
	}
	if changed {
		t.Fatal("checkHomebrewUpgrade() changed = true, want false")
	}
}

func TestCheckHomebrewUpgradeTimeout(t *testing.T) {
	resetUpdaterSeams(t)
	runCommand = func(ctx context.Context, _ string, args ...string) (string, error) {
		if args[0] == "list" {
			return "kontext-security/tap/kontext 1.2.3\n", nil
		}
		<-ctx.Done()
		return "", ctx.Err()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	changed, err := checkHomebrewUpgrade(ctx, "/opt/homebrew/bin/brew")
	if err == nil || !strings.Contains(err.Error(), "brew update-if-needed") {
		t.Fatalf("checkHomebrewUpgrade() error = %v, want update timeout error", err)
	}
	if changed {
		t.Fatal("checkHomebrewUpgrade() changed = true, want false")
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

func resetUpdaterSeams(t *testing.T) {
	t.Helper()
	runtimeGOOS = runtime.GOOS
	executablePath = os.Executable
	evalSymlinksPath = filepath.EvalSymlinks
	statPath = os.Stat
	runCommand = runCommandOutput
	t.Cleanup(func() {
		runtimeGOOS = runtime.GOOS
		executablePath = os.Executable
		evalSymlinksPath = filepath.EvalSymlinks
		statPath = os.Stat
		runCommand = runCommandOutput
	})
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
