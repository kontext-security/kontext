package managedobserve

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/kontext-security/kontext-cli/internal/profile"
)

const (
	DefaultLaunchdLabel = "security.kontext.managed-observe"

	// EnvExpectedConfigScope marks which managed-config scope a daemon was
	// installed for. The self-serve LaunchAgent sets it to "user"; the daemon
	// parks instead of running when the resolved scope differs, so an MDM
	// config appearing later is never served by the leftover self-serve agent.
	EnvExpectedConfigScope = "KONTEXT_EXPECTED_CONFIG_SCOPE"

	envSocketPath     = "KONTEXT_MANAGED_OBSERVE_SOCKET"
	envDBPath         = "KONTEXT_MANAGED_OBSERVE_DB"
	envIdleTimeout    = "KONTEXT_MANAGED_OBSERVE_IDLE_TIMEOUT"
	envLaunchdLabel   = "KONTEXT_MANAGED_OBSERVE_LAUNCHD_LABEL"
	defaultIdleWindow = 30 * time.Minute
)

func DefaultSocketPath() string {
	if path := strings.TrimSpace(os.Getenv(envSocketPath)); path != "" {
		return path
	}
	return filepath.Join("/tmp", fmt.Sprintf("kontext-managed-observe-%d", os.Getuid()), "kontext.sock")
}

// DefaultDBPath is the ledger cache location. With a profile active it is that
// profile's database, which is what fences the export backlog: the stream
// cursor and the policy cache both derive from the database's directory, so
// events captured for one workspace can never be flushed to another. Without a
// profile it is the legacy unprofiled path.
func DefaultDBPath() string {
	if path := strings.TrimSpace(os.Getenv(envDBPath)); path != "" {
		return path
	}
	if path, err := profile.ActiveDBPath(); err == nil {
		return path
	}
	return LegacyDBPath()
}

// LegacyDBPath is the pre-profile ledger cache location.
func LegacyDBPath() string {
	if path := profile.LegacyPath(filepath.Join(profile.ManagedObserveDir, profile.ManagedObserveDB)); path != "" {
		return path
	}
	// No resolvable home: keep the pre-profile relative fallback rather than
	// returning an empty path a caller would open as "".
	return filepath.Join(profile.ManagedObserveDir, profile.ManagedObserveDB)
}

func DefaultIdleTimeout() time.Duration {
	if value := strings.TrimSpace(os.Getenv(envIdleTimeout)); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
			return parsed
		}
	}
	return defaultIdleWindow
}

func DefaultLabel() string {
	if label := strings.TrimSpace(os.Getenv(envLaunchdLabel)); label != "" {
		return label
	}
	return DefaultLaunchdLabel
}

func EnsureSocketDir(socketPath string) error {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", dir)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("socket directory ownership is unavailable")
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("socket directory %s is owned by uid %d, want %d", dir, stat.Uid, os.Getuid())
	}
	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return err
		}
	}
	return nil
}
