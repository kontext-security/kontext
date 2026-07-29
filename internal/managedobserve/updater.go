package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
)

const (
	envNoUpdateCheck            = "KONTEXT_NO_UPDATE_CHECK"
	envDaemonUpdateInterval     = "KONTEXT_DAEMON_UPDATE_INTERVAL"
	defaultDaemonUpdateInterval = 24 * time.Hour
	brewListTimeout             = 15 * time.Second
	brewUpdateTimeout           = 2 * time.Minute
	brewUpgradeTimeout          = 5 * time.Minute
)

// homebrewFormulae maps the Cellar directory the running binary lives in to
// the formula the updater must upgrade. Staging installs live under
// Cellar/kontext-staging and must upgrade the staging formula — matching
// only Cellar/kontext left staging daemons permanently ineligible.
var homebrewFormulae = map[string]string{
	"kontext":         "kontext-security/tap/kontext",
	"kontext-staging": "kontext-security/tap/kontext-staging",
}

type commandRunner func(ctx context.Context, path string, args ...string) (string, error)

var (
	runtimeGOOS                    = runtime.GOOS
	executablePath                 = os.Executable
	evalSymlinksPath               = filepath.EvalSymlinks
	statPath                       = os.Stat
	runCommand       commandRunner = runCommandOutput
)

func startHomebrewUpdater(ctx context.Context, loadedConfig managedconfig.LoadedConfig, log diagnostic.Logger) <-chan struct{} {
	upgraded := make(chan struct{}, 1)
	cfg, ok := homebrewUpdaterConfig(ctx, loadedConfig, log)
	if !ok {
		close(upgraded)
		return upgraded
	}
	go runHomebrewUpdater(ctx, cfg, log, upgraded)
	return upgraded
}

type homebrewUpdaterConfigValue struct {
	brewPath string
	formula  string
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
	brewPath, formula, ok := currentExecutableBrewPath()
	if !ok {
		logHomebrewUpdater(log, "daemon updater eligibility: not a homebrew-managed install\n")
		return homebrewUpdaterConfigValue{}, false
	}
	if _, err := brewInstalledVersion(ctx, brewPath, formula); err != nil {
		logHomebrewUpdater(log, "daemon updater eligibility: brew list failed: %v\n", err)
		return homebrewUpdaterConfigValue{}, false
	}
	return homebrewUpdaterConfigValue{
		brewPath: brewPath,
		formula:  formula,
		interval: daemonUpdateInterval(),
	}, true
}

func runHomebrewUpdater(ctx context.Context, cfg homebrewUpdaterConfigValue, log diagnostic.Logger, upgraded chan<- struct{}) {
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, err := checkHomebrewUpgrade(ctx, cfg.brewPath, cfg.formula)
			if err != nil {
				logHomebrewUpdater(log, "daemon updater: %v\n", err)
				continue
			}
			if changed {
				logHomebrewUpdater(log, "daemon updater: upgraded %s; exiting for launchd restart\n", cfg.formula)
				select {
				case upgraded <- struct{}{}:
				default:
				}
				return
			}
		}
	}
}

func checkHomebrewUpgrade(ctx context.Context, brewPath string, formula string) (bool, error) {
	before, err := brewInstalledVersion(ctx, brewPath, formula)
	if err != nil {
		return false, fmt.Errorf("version before upgrade: %w", err)
	}
	if _, err := runBrewWithTimeout(ctx, brewUpdateTimeout, brewPath, "update-if-needed"); err != nil {
		return false, fmt.Errorf("brew update-if-needed: %w", err)
	}
	if _, err := runBrewWithTimeout(ctx, brewUpgradeTimeout, brewPath, "upgrade", "--formula", "--no-ask", formula); err != nil {
		return false, fmt.Errorf("brew upgrade: %w", err)
	}
	after, err := brewInstalledVersion(ctx, brewPath, formula)
	if err != nil {
		return false, fmt.Errorf("version after upgrade: %w", err)
	}
	return after != "" && before != after, nil
}

func brewInstalledVersion(ctx context.Context, brewPath string, formula string) (string, error) {
	output, err := runBrewWithTimeout(ctx, brewListTimeout, brewPath, "list", "--versions", formula)
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

func currentExecutableBrewPath() (string, string, bool) {
	exe, err := executablePath()
	if err != nil {
		return "", "", false
	}
	resolved, err := evalSymlinksPath(exe)
	if err != nil {
		return "", "", false
	}
	for _, path := range []string{"/opt/homebrew/bin/brew", "/usr/local/bin/brew"} {
		prefix := strings.TrimSuffix(path, "/bin/brew")
		formula, ok := homebrewFormulaForCellar(resolved, prefix)
		if !ok {
			continue
		}
		info, err := statPath(path)
		if err == nil && !info.IsDir() {
			return path, formula, true
		}
	}
	return "", "", false
}

// homebrewFormulaForCellar matches the resolved executable against the
// prefix's Cellar and returns the formula that owns that Cellar directory.
func homebrewFormulaForCellar(resolved, prefix string) (string, bool) {
	cellarRoot := prefix + "/Cellar/"
	if !strings.HasPrefix(resolved, cellarRoot) {
		return "", false
	}
	rest := strings.TrimPrefix(resolved, cellarRoot)
	cellar, _, found := strings.Cut(rest, "/")
	if !found {
		return "", false
	}
	formula, ok := homebrewFormulae[cellar]
	return formula, ok
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
