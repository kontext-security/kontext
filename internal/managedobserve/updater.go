package managedobserve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kontext-security/kontext/internal/buildinfo"
	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/managedconfig"
	"github.com/kontext-security/kontext/internal/profile"
)

const (
	envNoUpdateCheck            = "KONTEXT_NO_UPDATE_CHECK"
	envDaemonUpdateInterval     = "KONTEXT_DAEMON_UPDATE_INTERVAL"
	homebrewFormula             = "kontext-security/tap/kontext"
	defaultDaemonUpdateInterval = 6 * time.Hour
	brewListTimeout             = 15 * time.Second
	brewUpdateTimeout           = 2 * time.Minute
	brewUpgradeTimeout          = 5 * time.Minute
	// Homebrew refreshes its taps for our check at most this often (seconds).
	brewAutoUpdateSecs = "3600"
)

type commandRunner func(ctx context.Context, env []string, path string, args ...string) (string, error)

var (
	runtimeGOOS                    = runtime.GOOS
	executablePath                 = os.Executable
	evalSymlinksPath               = filepath.EvalSymlinks
	statPath                       = os.Stat
	runCommand       commandRunner = runCommandOutput
	homebrewBuild                  = buildinfo.HomebrewBuild
	updateStatePath                = func() string { return filepath.Join(profile.Root(), "update-check.json") }
	// The first check waits for the daemon to settle; later wakes compare the
	// wall clock with the saved check time. Go timers on macOS stop while the
	// Mac sleeps, and a restart starts them over, so neither may pace checks.
	firstUpdateCheckDelay = 2 * time.Minute
	updateWakeInterval    = 10 * time.Minute
)

// homebrewInstall is the Homebrew package that owns the running binary.
type homebrewInstall struct {
	brewPath string
	// kind is "--formula" or "--cask": the tap ships kontext as both, and brew
	// only upgrades the one that is installed.
	kind    string
	version string
	// link is <prefix>/bin/kontext, the stable path hooks and the LaunchAgent use.
	link string
}

// UpdateState is the last update check, shared with doctor.
type UpdateState struct {
	CheckedAt time.Time `json:"checked_at"`
	Source    string    `json:"source"`
	Error     string    `json:"error,omitempty"`
	Notice    string    `json:"notice,omitempty"`
}

func startHomebrewUpdater(ctx context.Context, loadedConfig managedconfig.LoadedConfig, log diagnostic.Logger) <-chan struct{} {
	upgraded := make(chan struct{}, 1)
	install, ok := homebrewUpdaterInstall(loadedConfig, log)
	if !ok {
		close(upgraded)
		return upgraded
	}
	check := func(ctx context.Context) (bool, string, error) {
		return checkHomebrewUpgrade(ctx, install, log)
	}
	if homebrewBuild() {
		// homebrew-core does not allow self-updating formulae: notice only.
		check = func(ctx context.Context) (bool, string, error) {
			// brew outdated reads cached metadata; refresh it first.
			_, refreshErr := runBrewWithTimeout(ctx, brewUpdateTimeout, []string{"HOMEBREW_AUTO_UPDATE_SECS=" + brewAutoUpdateSecs}, install.brewPath, "update-if-needed")
			if ctx.Err() != nil {
				return false, "", ctx.Err()
			}
			notice, err := homebrewOutdatedWarning(ctx, install.brewPath)
			if notice != "" {
				logHomebrewUpdater(log, "%s\n", notice)
			}
			// Stale metadata that shows nothing new proves nothing: retry soon.
			if err == nil && notice == "" && refreshErr != nil {
				err = fmt.Errorf("brew update-if-needed: %w", refreshErr)
			}
			return false, notice, err
		}
	}
	go runUpdateSchedule(ctx, updateSource(install), daemonUpdateInterval(), check, log, upgraded)
	return upgraded
}

func homebrewUpdaterInstall(loadedConfig managedconfig.LoadedConfig, log diagnostic.Logger) (homebrewInstall, bool) {
	if runtimeGOOS != "darwin" || loadedConfig.Scope != managedconfig.ScopeUser {
		return homebrewInstall{}, false
	}
	if strings.TrimSpace(os.Getenv(envNoUpdateCheck)) != "" {
		return homebrewInstall{}, false
	}
	install, ok := currentHomebrewInstall()
	if !ok {
		exe, _ := executablePath()
		logHomebrewUpdater(log, "daemon updater: off, %s is not a Homebrew install under /opt/homebrew or /usr/local\n", exe)
		return homebrewInstall{}, false
	}
	return install, true
}

func updateSource(install homebrewInstall) string {
	switch {
	case homebrewBuild():
		return "homebrew-core"
	case install.kind == "--cask":
		return "cask"
	default:
		return "tap formula"
	}
}

func runUpdateSchedule(ctx context.Context, source string, interval time.Duration, check func(context.Context) (bool, string, error), log diagnostic.Logger, upgraded chan<- struct{}) {
	wait := firstUpdateCheckDelay
	// The last check this process ran, for when the saved file cannot be written.
	var last UpdateState
	for {
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		wait = min(updateWakeInterval, interval)
		// The saved time carries no monotonic reading, so this compares wall
		// clocks, which keep counting across sleep and restarts. A check saved
		// by another package (homebrew-core before a switch to the cask) does
		// not count.
		// A saved time in the future (a clock that was ahead) is due at once.
		state, err := LoadUpdateState()
		if err != nil || state.Source != source {
			state = last
		}
		if state.Source == source {
			// A failed check (offline after wake, brew busy) retries within the hour.
			limit := interval
			if state.Error != "" {
				limit = min(interval, time.Hour)
			}
			if elapsed := time.Since(state.CheckedAt); elapsed >= 0 && elapsed < limit {
				continue
			}
		}
		changed, notice, err := check(ctx)
		if ctx.Err() != nil {
			return
		}
		state = UpdateState{CheckedAt: time.Now(), Source: source, Notice: notice}
		if err != nil {
			state.Error = err.Error()
			logHomebrewUpdater(log, "daemon updater: %v\n", err)
		}
		last = state
		if writeErr := writeJSONBreadcrumb(updateStatePath(), state); writeErr != nil {
			logHomebrewUpdater(log, "daemon updater: save check time: %v\n", writeErr)
		}
		if changed {
			logHomebrewUpdater(log, "daemon updater: upgraded %s; exiting for launchd restart\n", homebrewFormula)
			select {
			case upgraded <- struct{}{}:
			default:
			}
			return
		}
	}
}

// LoadUpdateState reads the last update check.
func LoadUpdateState() (UpdateState, error) {
	var state UpdateState
	data, err := os.ReadFile(updateStatePath())
	if err == nil {
		err = json.Unmarshal(data, &state)
	}
	return state, err
}

func homebrewOutdatedWarning(ctx context.Context, brewPath string) (string, error) {
	output, err := runBrewWithTimeout(ctx, brewListTimeout, nil, brewPath, "outdated", "--formula", "--json=v2", "kontext")
	if err != nil {
		return "", fmt.Errorf("brew outdated: %w", err)
	}
	var outdated struct {
		Formulae []struct {
			Name              string   `json:"name"`
			InstalledVersions []string `json:"installed_versions"`
			CurrentVersion    string   `json:"current_version"`
		} `json:"formulae"`
	}
	if err := json.Unmarshal([]byte(output), &outdated); err != nil {
		return "", fmt.Errorf("parse brew outdated: %w", err)
	}
	for _, formula := range outdated.Formulae {
		if formula.Name == "kontext" {
			if len(formula.InstalledVersions) == 0 || formula.CurrentVersion == "" {
				return "", fmt.Errorf("unexpected brew outdated output %q", strings.TrimSpace(output))
			}
			return fmt.Sprintf("kontext %s is outdated; %s is available. Run: brew upgrade kontext",
				strings.Join(formula.InstalledVersions, ", "), formula.CurrentVersion), nil
		}
	}
	return "", nil
}

// checkHomebrewUpgrade refreshes Homebrew's taps, then upgrades kontext. A
// failed refresh does not stop the upgrade: one broken tap fails `brew update`
// while every other tap, ours included, still updates. The refresh failure
// comes back as a notice, so doctor shows it.
func checkHomebrewUpgrade(ctx context.Context, install homebrewInstall, log diagnostic.Logger) (bool, string, error) {
	notice := ""
	if _, err := runBrewWithTimeout(ctx, brewUpdateTimeout, []string{"HOMEBREW_AUTO_UPDATE_SECS=" + brewAutoUpdateSecs}, install.brewPath, "update-if-needed"); err != nil {
		if ctx.Err() != nil {
			return false, "", err
		}
		notice = fmt.Sprintf("brew update-if-needed failed (%v); the check used the last fetched tap", err)
		logHomebrewUpdater(log, "daemon updater: %s\n", notice)
	}
	if _, err := runBrewWithTimeout(ctx, brewUpgradeTimeout, []string{"HOMEBREW_NO_AUTO_UPDATE=1"}, install.brewPath, "upgrade", install.kind, "--no-ask", homebrewFormula); err != nil {
		return false, notice, fmt.Errorf("brew upgrade: %w", err)
	}
	after, err := evalSymlinksPath(install.link)
	if err != nil {
		return false, notice, fmt.Errorf("version after upgrade: %w", err)
	}
	version := homebrewVersion(after)
	changed := version != "" && version != install.version
	// Nothing to upgrade on a tap that could not be refreshed (offline after
	// wake) is not a finished check: fail it so it retries within the hour.
	if !changed && notice != "" {
		return false, "", errors.New(notice)
	}
	return changed, notice, nil
}

func runBrewWithTimeout(parent context.Context, timeout time.Duration, env []string, brewPath string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	output, err := runCommand(ctx, env, brewPath, args...)
	if ctx.Err() != nil {
		return output, ctx.Err()
	}
	return output, err
}

// currentHomebrewInstall reads the package from the running binary's resolved
// path, <prefix>/Caskroom/kontext/<version>/… or <prefix>/Cellar/kontext/<version>/…,
// so starting the daemon never waits on brew itself. Only the two standard
// prefixes count: setup gives hooks and the LaunchAgent a stable path there,
// while a custom prefix leaves them on a versioned path an upgrade removes.
func currentHomebrewInstall() (homebrewInstall, bool) {
	exe, err := executablePath()
	if err != nil {
		return homebrewInstall{}, false
	}
	resolved, err := evalSymlinksPath(exe)
	if err != nil {
		return homebrewInstall{}, false
	}
	for marker, kind := range map[string]string{"/Caskroom/kontext/": "--cask", "/Cellar/kontext/": "--formula"} {
		prefix, _, found := strings.Cut(resolved, marker)
		if !found || prefix != "/opt/homebrew" && prefix != "/usr/local" {
			continue
		}
		brew := filepath.Join(prefix, "bin", "brew")
		if info, err := statPath(brew); err != nil || info.IsDir() {
			return homebrewInstall{}, false
		}
		return homebrewInstall{brewPath: brew, kind: kind, version: homebrewVersion(resolved), link: filepath.Join(prefix, "bin", "kontext")}, true
	}
	return homebrewInstall{}, false
}

// currentExecutableBrewPath returns the brew that owns the running binary and
// whether it was installed as a formula (Cellar) or a cask (Caskroom).
func currentExecutableBrewPath() (string, string, bool) {
	install, ok := currentHomebrewInstall()
	return install.brewPath, install.kind, ok
}

func homebrewVersion(resolved string) string {
	for _, marker := range []string{"/Caskroom/kontext/", "/Cellar/kontext/"} {
		if _, rest, found := strings.Cut(resolved, marker); found {
			version, _, _ := strings.Cut(rest, "/")
			return version
		}
	}
	return ""
}

func daemonUpdateInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv(envDaemonUpdateInterval))
	if raw == "" {
		return defaultDaemonUpdateInterval
	}
	interval, err := time.ParseDuration(raw)
	if err != nil || interval <= 0 {
		return defaultDaemonUpdateInterval
	}
	return interval
}

func runCommandOutput(ctx context.Context, env []string, path string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return string(output), ctx.Err()
		}
		return string(output), fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func logHomebrewUpdater(log diagnostic.Logger, format string, args ...any) {
	logAlways(log, format, args...)
}
