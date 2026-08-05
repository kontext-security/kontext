package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/kontext-security/kontext-cli/internal/diagnostic"
)

const (
	envBinaryWatchInterval     = "KONTEXT_BINARY_WATCH_INTERVAL"
	defaultBinaryWatchInterval = 2 * time.Minute
)

var errBinaryWatchdogUnsupported = errors.New("binary watchdog is only supported on macOS")

type binaryWatchdogConfigValue struct {
	exe         string
	resolved    string
	initialInfo os.FileInfo
	interval    time.Duration
	stat        func(string) (os.FileInfo, error)
	resolve     func(string) (string, error)
}

// startBinaryWatchdog exits after launchd KeepAlive leaves an old deleted
// binary running across brew upgrades; a clean exit lets launchd respawn the
// new binary. Replacement is detected three ways: the resolved binary file
// disappears (brew removes the old Cellar version dir), its inode changes
// (inode replacement), or the launch path resolves to a different target
// (brew retargets the bin symlink but keeps the old keg, e.g. under
// HOMEBREW_NO_INSTALL_CLEANUP).
func startBinaryWatchdog(ctx context.Context, log diagnostic.Logger) <-chan struct{} {
	replaced := make(chan struct{}, 1)
	cfg, err := binaryWatchdogConfig()
	if errors.Is(err, fs.ErrNotExist) {
		// The old binary can disappear after launchd starts this process but
		// before the watchdog captures its baseline. That is already proof of an
		// upgrade, so exit instead of disabling the watchdog for this run.
		signalBinaryReplaced(cfg.exe, log, replaced)
		return replaced
	}
	if err != nil {
		if !errors.Is(err, errBinaryWatchdogUnsupported) {
			logAlways(log, "binary watchdog eligibility: %v\n", err)
		}
		close(replaced)
		return replaced
	}
	go runBinaryWatchdog(ctx, cfg, log, replaced)
	return replaced
}

func binaryWatchdogConfig() (binaryWatchdogConfigValue, error) {
	cfg := binaryWatchdogConfigValue{
		interval: binaryWatchInterval(),
		stat:     statPath,
		resolve:  evalSymlinksPath,
	}
	if runtimeGOOS != "darwin" {
		return cfg, errBinaryWatchdogUnsupported
	}
	exe, err := executablePath()
	cfg.exe = exe
	if err != nil {
		return cfg, fmt.Errorf("executable path: %w", err)
	}
	resolved, err := cfg.resolve(exe)
	cfg.resolved = resolved
	if err != nil {
		return cfg, fmt.Errorf("resolve executable %s: %w", exe, err)
	}
	info, err := cfg.stat(resolved)
	cfg.initialInfo = info
	if err != nil {
		return cfg, fmt.Errorf("stat executable %s: %w", resolved, err)
	}
	return cfg, nil
}

func runBinaryWatchdog(ctx context.Context, cfg binaryWatchdogConfigValue, log diagnostic.Logger, replaced chan<- struct{}) {
	ticker := time.NewTicker(cfg.interval)
	defer ticker.Stop()
	loggedStatErr := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			currentInfo, err := cfg.stat(cfg.resolved)
			if errors.Is(err, fs.ErrNotExist) {
				signalBinaryReplaced(cfg.resolved, log, replaced)
				return
			}
			if err != nil {
				// Log once per error burst; reset below so a recurrence
				// after recovery is surfaced again.
				if !loggedStatErr {
					logAlways(log, "binary watchdog: stat %s: %v\n", cfg.resolved, err)
					loggedStatErr = true
				}
				continue
			}
			loggedStatErr = false
			if !os.SameFile(cfg.initialInfo, currentInfo) {
				signalBinaryReplaced(cfg.resolved, log, replaced)
				return
			}
			// Resolve errors are transient (brew swaps the symlink
			// non-atomically); only a successful resolve to a new target
			// counts as replacement.
			if current, err := cfg.resolve(cfg.exe); err == nil && current != cfg.resolved {
				signalBinaryReplaced(cfg.resolved, log, replaced)
				return
			}
		}
	}
}

func signalBinaryReplaced(resolved string, log diagnostic.Logger, replaced chan<- struct{}) {
	logAlways(log, "binary watchdog: %s was replaced on disk; exiting for launchd restart\n", resolved)
	select {
	case replaced <- struct{}{}:
	default:
	}
}

func binaryWatchInterval() time.Duration {
	raw := strings.TrimSpace(os.Getenv(envBinaryWatchInterval))
	if raw == "" {
		return defaultBinaryWatchInterval
	}
	interval, err := time.ParseDuration(raw)
	if err != nil || interval <= 0 {
		return defaultBinaryWatchInterval
	}
	return interval
}

func logAlways(log diagnostic.Logger, format string, args ...any) {
	diagnostic.LogAlways(log, format, args...)
}
