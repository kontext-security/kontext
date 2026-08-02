package managedobserve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedstream"
)

// PrintStatus reports the managed-observe state for `kontext doctor`:
// which managed config (if any) this machine resolves, the installation
// identity, whether the daemon is reachable, the self-serve LaunchAgent, and
// any token-rejection breadcrumb the daemon left behind.
// DoctorStatus is the managed-observe health result. Repairable is deliberately
// narrower than Healthy: --fix only performs a repair that is known safe.
type DoctorStatus struct {
	Configured bool
	SelfServe  bool
	Healthy    bool
	Repairable bool
}

func PrintStatus(out io.Writer, installedVersion string) DoctorStatus {
	return printStatus(out, installedVersion, doctorOptions{
		DBPath:     DefaultDBPath(),
		SocketPath: DefaultSocketPath(),
		Now:        time.Now,
	})
}

type doctorOptions struct {
	DBPath             string
	SocketPath         string
	Dial               func(network, address string, timeout time.Duration) (net.Conn, error)
	Now                func() time.Time
	LaunchAgentPresent func() bool
}

func printStatus(out io.Writer, installedVersion string, opts doctorOptions) DoctorStatus {
	status := DoctorStatus{Healthy: true}
	staleDaemon := false
	repairTargetAvailable := false
	if opts.DBPath == "" {
		opts.DBPath = DefaultDBPath()
	}
	if opts.SocketPath == "" {
		opts.SocketPath = DefaultSocketPath()
	}
	if opts.Dial == nil {
		opts.Dial = net.DialTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.LaunchAgentPresent == nil {
		opts.LaunchAgentPresent = selfServeLaunchAgentPresent
	}

	fmt.Fprintln(out, "Managed observe:")

	loaded, err := managedconfig.Load()
	if errors.Is(err, managedconfig.ErrNotManaged) {
		fmt.Fprintln(out, "  config: not configured (run `kontext setup` to connect this Mac to a workspace)")
		return status
	}
	if err != nil {
		fmt.Fprintf(out, "  config: ERROR %v\n", err)
		status.Healthy = false
		return status
	}
	status.Configured = true
	status.SelfServe = loaded.Scope == managedconfig.ScopeUser

	fmt.Fprintf(out, "  config: %s (%s)\n", loaded.Path, describeScope(loaded.Scope))
	launchAgentPresent := opts.LaunchAgentPresent()
	repairTargetAvailable = runtime.GOOS == "darwin" && loaded.Scope == managedconfig.ScopeUser && launchAgentPresent
	if loaded.Scope == managedconfig.ScopeUser && !launchAgentPresent {
		fmt.Fprintln(out, "  launch agent: missing (run `kontext setup` to restore the background agent)")
		status.Healthy = false
	}

	identityPath := installationPathForScope(loaded.Scope)
	if state, err := installation.LoadFile(identityPath); err == nil {
		fmt.Fprintf(out, "  installation: %s\n", state.InstallationID)
	} else if errors.Is(err, installation.ErrNotFound) {
		fmt.Fprintf(out, "  installation: not created yet (%s)\n", identityPath)
		status.Healthy = false
	} else {
		fmt.Fprintf(out, "  installation: ERROR %v (%s)\n", err, identityPath)
		status.Healthy = false
	}

	// Resolve the token through the daemon's exact read path: a locked or
	// missing keychain item is THE silent killer under launchd, and "daemon:
	// not running" alone points the user in the wrong direction.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := managedconfig.ResolveInstallToken(ctx, loaded.Config.Credentials.InstallTokenRef); err == nil {
		fmt.Fprintf(out, "  install token: readable (%s)\n", loaded.Config.Credentials.InstallTokenRef)
	} else {
		fmt.Fprintf(out, "  WARNING: install token is not readable (%v) — the agent cannot stream; re-run `kontext setup` or unlock your login keychain\n", err)
		status.Healthy = false
	}

	if conn, err := opts.Dial("unix", opts.SocketPath, 500*time.Millisecond); err == nil {
		conn.Close()
		if daemonStatus := LoadDaemonStatus(opts.DBPath); daemonStatus != nil && pidAlive(daemonStatus.PID) {
			fmt.Fprintf(out, "  daemon: running (v%s, pid %d)\n", daemonStatus.Version, daemonStatus.PID)
			if comparableVersion(daemonStatus.Version) && comparableVersion(installedVersion) && daemonStatus.Version != installedVersion {
				if repairTargetAvailable {
					fmt.Fprintf(out, "  WARNING: daemon is running v%s but v%s is installed — run 'kontext doctor --fix' to restart it\n", daemonStatus.Version, installedVersion)
				} else {
					fmt.Fprintf(out, "  WARNING: daemon is running v%s but v%s is installed — restart it through its managing installation\n", daemonStatus.Version, installedVersion)
				}
				staleDaemon = true
			}
		} else {
			fmt.Fprintln(out, "  daemon: running")
			// A serving daemon with no live status breadcrumb predates the
			// breadcrumb feature — which makes it older than the installed
			// binary by definition. This is exactly the first upgrade into
			// this feature, so it must be fixable; a verified restart of an
			// already-current daemon is the harmless worst case.
			if comparableVersion(installedVersion) {
				if repairTargetAvailable {
					fmt.Fprintf(out, "  WARNING: daemon version is unknown — it likely predates v%s; run 'kontext doctor --fix' to restart it\n", installedVersion)
				} else {
					fmt.Fprintf(out, "  WARNING: daemon version is unknown — restart it through its managing installation\n")
				}
				staleDaemon = true
			}
		}
	} else {
		fmt.Fprintln(out, "  daemon: not running (it starts with your next Claude Code session)")
		status.Healthy = false
	}

	exportCtx, exportCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer exportCancel()
	state, err := managedstream.LoadState(managedstream.DefaultStatePathForDB(opts.DBPath))
	if err != nil {
		fmt.Fprintf(out, "  heartbeat: ERROR %v\n", err)
		fmt.Fprintf(out, "  export: ERROR %v\n", err)
		status.Healthy = false
	} else {
		if !printHeartbeat(out, state, opts.Now()) {
			status.Healthy = false
		}
		if !printExportLag(exportCtx, out, opts.DBPath, state) {
			status.Healthy = false
		}
	}

	// Self-serve installs have a user LaunchAgent; MDM installs manage theirs
	// under /Library. Having BOTH scopes on one Mac deserves a callout — the
	// system config wins and the user agent should be removed.
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		userPlist := filepath.Join(home, "Library", "LaunchAgents", DefaultLaunchdLabel+".plist")
		if launchAgentPresent {
			fmt.Fprintf(out, "  launch agent: %s\n", userPlist)
			if loaded.Scope == managedconfig.ScopeSystem {
				fmt.Fprintln(out, "  WARNING: this Mac is organization-managed but a self-serve agent is also installed; run `kontext setup --uninstall` to remove it")
				status.Healthy = false
			}
		}
	}

	// The LaunchAgent runs the daemon without --db, so the breadcrumb always
	// sits next to the default database. A custom --db (dev-only hidden flag)
	// is invisible here — acceptable for a diagnostics readout.
	if authErr := LoadAuthError(opts.DBPath); authErr != nil {
		status.Healthy = false
		switch authErr.Kind {
		case "startup":
			fmt.Fprintf(out, "  WARNING: the agent failed to start — %s (%s)\n", authErr.Message, authErr.At)
		case authErrorKindCorrupt:
			fmt.Fprintf(out, "  WARNING: auth breadcrumb is unreadable — %s\n", authErr.Message)
		default:
			detail := ""
			if authErr.Status > 0 {
				detail = fmt.Sprintf(" (HTTP %d, %s)", authErr.Status, authErr.At)
			}
			fmt.Fprintf(out, "  WARNING: hosted ingest is failing — install token rejected%s; run `kontext setup` with a new token from the dashboard\n", detail)
		}
	}
	// Restarting a stale daemon is safe only when every other prerequisite is
	// healthy and the self-serve LaunchAgent is a verified Darwin repair target.
	status.Repairable = staleDaemon && status.Healthy && repairTargetAvailable
	if staleDaemon {
		status.Healthy = false
	}
	return status
}

func selfServeLaunchAgentPresent() bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	path := filepath.Join(home, "Library", "LaunchAgents", DefaultLaunchdLabel+".plist")
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func describeScope(scope managedconfig.Scope) string {
	switch scope {
	case managedconfig.ScopeSystem:
		return "system, managed by your organization"
	case managedconfig.ScopeUser:
		return "user, installed by kontext setup"
	case managedconfig.ScopeEnv:
		return "env override"
	default:
		return string(scope)
	}
}

// WaitForDaemonRestart polls until the socket is serving AND the status
// breadcrumb reports a live daemon on wantVersion (any live daemon when the
// version is not comparable, e.g. dev builds). `doctor --fix` uses it so
// "restarted" is only printed for a verified comeback — launchd can accept a
// kickstart and still have the new daemon exit immediately (unreadable token,
// missing Cellar path).
func WaitForDaemonRestart(ctx context.Context, dbPath, socketPath, wantVersion string) (*DaemonStatus, error) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond); err == nil {
			conn.Close()
			if status := LoadDaemonStatus(dbPath); status != nil && pidAlive(status.PID) {
				if !comparableVersion(wantVersion) || status.Version == wantVersion {
					return status, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func comparableVersion(version string) bool {
	version = strings.TrimSpace(version)
	return version != "" && version != "dev"
}

func printHeartbeat(out io.Writer, state managedstream.State, now time.Time) bool {
	if strings.TrimSpace(state.LastHeartbeatAt) == "" {
		fmt.Fprintln(out, "  heartbeat: none recorded yet (the daemon has not reported healthy)")
		return false
	}
	last, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(state.LastHeartbeatAt))
	if err != nil {
		fmt.Fprintln(out, "  heartbeat: ERROR invalid timestamp")
		return false
	}
	age := now.Sub(last)
	if age < 0 {
		age = 0
	}
	fmt.Fprintf(out, "  heartbeat: %s ago\n", doctorDuration(age))
	if age > 5*time.Minute {
		fmt.Fprintf(out, "  WARNING: last heartbeat was %s ago — the daemon may be stalled\n", doctorDuration(age))
		return false
	}
	return true
}

func printExportLag(ctx context.Context, out io.Writer, dbPath string, state managedstream.State) bool {
	var cursor *sqlite.LedgerCursor
	if state.UpdatedAfter != nil {
		cursor = &sqlite.LedgerCursor{UpdatedAt: *state.UpdatedAfter, ActionID: state.ActionID}
	}
	newest, pending, err := sqlite.LedgerLag(ctx, dbPath, cursor)
	if err != nil {
		fmt.Fprintf(out, "  export: ERROR %v\n", err)
		return false
	}
	if newest == nil {
		fmt.Fprintln(out, "  export: no ledger events yet")
		return true
	}
	if cursor == nil {
		fmt.Fprintf(out, "  export: not started yet (%d pending)\n", pending)
		return false
	}
	lag := newest.Sub(cursor.UpdatedAt)
	if lag < 0 {
		lag = 0
	}
	// The export cursor rides 30s behind newest by design (cursorSafetyLag),
	// hence the 10m warning threshold.
	if lag > 10*time.Minute && pending > 0 {
		fmt.Fprintf(out, "  WARNING: export lagging %s (%d events pending) — the daemon may be stalled\n", doctorDuration(lag), pending)
		return false
	}
	if pending == 0 {
		fmt.Fprintln(out, "  export: up to date (0 pending)")
		return true
	}
	// Never claim "up to date" while rows are waiting — report the facts and
	// let the operator judge.
	fmt.Fprintf(out, "  export: %d pending (cursor %s behind newest)\n", pending, doctorDuration(lag))
	return true
}

func doctorDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Minute).String()
}
