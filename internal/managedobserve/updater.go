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
)

const (
	envNoUpdateCheck            = "KONTEXT_NO_UPDATE_CHECK"
	envDaemonUpdateInterval     = "KONTEXT_DAEMON_UPDATE_INTERVAL"
	homebrewFormula             = "kontext-security/tap/kontext"
	defaultDaemonUpdateInterval = 24 * time.Hour
	brewListTimeout             = 15 * time.Second
	brewUpdateTimeout           = 2 * time.Minute
	brewUpgradeTimeout          = 5 * time.Minute
)

type commandRunner func(ctx context.Context, path string, args ...string) (string, error)

var (
	runtimeGOOS                    = runtime.GOOS
	executablePath                 = os.Executable
	evalSymlinksPath               = filepath.EvalSymlinks
	statPath                       = os.Stat
	runCommand       commandRunner = runCommandOutput
	homebrewBuild                  = buildinfo.HomebrewBuild
)

func startHomebrewUpdater(ctx context.Context, loadedConfig managedconfig.LoadedConfig, log diagnostic.Logger) <-chan struct{} {
	upgraded := make(chan struct{}, 1)
	cfg, ok := homebrewUpdaterConfig(ctx, loadedConfig, log)
	if !ok {
		if homebrewBuild() && cfg.brewPath != "" {
			go runHomebrewOutdatedChecker(ctx, cfg, log)
		}
		close(upgraded)
		return upgraded
	}
	go runHomebrewUpdater(ctx, cfg, log, upgraded)
	return upgraded
}

type homebrewUpdaterConfigValue struct {
	brewPath string
	interval time.Duration
}

func homebrewUpdaterConfig(ctx context.Context, loadedConfig managedconfig.LoadedConfig, log diagnostic.Logger) (homebrewUpdaterConfigValue, bool) {
	if runtimeGOOS != "darwin" {
		return homebrewUpdaterConfigValue{}, false
	}
	if loadedConfig.Scope != managedconfig.ScopeUser {
		return homebrewUpdaterConfigValue{}, false
	}
	if strings.TrimSpace(os.Getenv(envNoUpdateCheck)) != "" {
		return homebrewUpdaterConfigValue{}, false
	}
	brewPath, ok := currentExecutableBrewPath()
	if !ok {
		logHomebrewUpdater(log, "daemon updater eligibility: brew not found\n")
		return homebrewUpdaterConfigValue{}, false
	}
	cfg := homebrewUpdaterConfigValue{brewPath: brewPath, interval: daemonUpdateInterval()}
	if homebrewBuild() {
		logHomebrewUpdater(log, "daemon updater: auto-update is disabled because kontext was installed from homebrew-core; run: brew upgrade kontext\n")
		// Keep the eligible path for read-only notices, but never enable upgrades.
		return cfg, false
	}
	if _, err := brewInstalledVersion(ctx, brewPath); err != nil {
		logHomebrewUpdater(log, "daemon updater eligibility: brew list failed: %v\n", err)
		return homebrewUpdaterConfigValue{}, false
	}
	return cfg, true
}

func runHomebrewOutdatedChecker(ctx context.Context, cfg homebrewUpdaterConfigValue, log diagnostic.Logger) {
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := runBrewWithTimeout(ctx, brewUpdateTimeout, cfg.brewPath, "update-if-needed"); err != nil {
				logHomebrewUpdater(log, "daemon updater: brew update-if-needed: %v\n", err)
				continue
			}
			warning, err := homebrewOutdatedWarning(ctx, cfg.brewPath)
			if err != nil {
				logHomebrewUpdater(log, "daemon updater: %v\n", err)
			} else if warning != "" {
				logHomebrewUpdater(log, "%s\n", warning)
			}
		}
	}
}

func homebrewOutdatedWarning(ctx context.Context, brewPath string) (string, error) {
	output, err := runBrewWithTimeout(ctx, brewListTimeout, brewPath, "outdated", "--formula", "--json=v2", "kontext")
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

func runHomebrewUpdater(ctx context.Context, cfg homebrewUpdaterConfigValue, log diagnostic.Logger, upgraded chan<- struct{}) {
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, err := checkHomebrewUpgrade(ctx, cfg.brewPath)
			if err != nil {
				logHomebrewUpdater(log, "daemon updater: %v\n", err)
				continue
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
}

func checkHomebrewUpgrade(ctx context.Context, brewPath string) (bool, error) {
	before, err := brewInstalledVersion(ctx, brewPath)
	if err != nil {
		return false, fmt.Errorf("version before upgrade: %w", err)
	}
	if _, err := runBrewWithTimeout(ctx, brewUpdateTimeout, brewPath, "update-if-needed"); err != nil {
		return false, fmt.Errorf("brew update-if-needed: %w", err)
	}
	if _, err := runBrewWithTimeout(ctx, brewUpgradeTimeout, brewPath, "upgrade", "--formula", "--no-ask", homebrewFormula); err != nil {
		return false, fmt.Errorf("brew upgrade: %w", err)
	}
	after, err := brewInstalledVersion(ctx, brewPath)
	if err != nil {
		return false, fmt.Errorf("version after upgrade: %w", err)
	}
	return after != "" && before != after, nil
}

func brewInstalledVersion(ctx context.Context, brewPath string) (string, error) {
	output, err := runBrewWithTimeout(ctx, brewListTimeout, brewPath, "list", "--versions", homebrewFormula)
	if err != nil {
		return "", err
	}
	fields := strings.Fields(output)
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected brew list output %q", strings.TrimSpace(output))
	}
	return fields[len(fields)-1], nil
}

func runBrewWithTimeout(parent context.Context, timeout time.Duration, brewPath string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	output, err := runCommand(ctx, brewPath, args...)
	if ctx.Err() != nil {
		return output, ctx.Err()
	}
	return output, err
}

func currentExecutableBrewPath() (string, bool) {
	exe, err := executablePath()
	if err != nil {
		return "", false
	}
	resolved, err := evalSymlinksPath(exe)
	if err != nil {
		return "", false
	}
	for _, path := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		prefix := strings.TrimSuffix(path, "/bin/brew")
		if !strings.HasPrefix(resolved, prefix+"/Cellar/kontext/") {
			continue
		}
		info, err := statPath(path)
		if err == nil && !info.IsDir() {
			return path, true
		}
	}
	return "", false
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

func runCommandOutput(ctx context.Context, path string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, path, args...)
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
