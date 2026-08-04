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

	"github.com/kontext-security/kontext-cli/internal/buildinfo"
	"github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedstream"
	"github.com/kontext-security/kontext-cli/internal/profile"
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

// Report is the machine-readable form of a doctor run — with `profile ls
// --json`, one of the two surfaces a GUI is expected to build on. It carries
// what a status indicator renders: whether things are healthy, which profile is
// active, whether the daemon is alive, and how far behind the export is.
//
// Pointers distinguish "not measured" from a zero measurement: a heartbeat that
// has never been recorded is not the same as one zero seconds old.
type Report struct {
	Healthy    bool `json:"healthy"`
	Configured bool `json:"configured"`
	SelfServe  bool `json:"self_serve"`
	Repairable bool `json:"repairable"`

	ActiveProfile string `json:"active_profile,omitempty"`
	// LegacyInstall reports an install still resolving the pre-profile paths.
	LegacyInstall bool   `json:"legacy_install"`
	ConfigPath    string `json:"config_path,omitempty"`
	ConfigScope   string `json:"config_scope,omitempty"`
	CloudURL      string `json:"cloud_url,omitempty"`
	Mode          string `json:"mode,omitempty"`
	// AllowHTTPLoopback reports that this profile accepts plaintext http to a
	// loopback backend — a local-development posture, surfaced so it is visible
	// rather than inferred from the URL.
	AllowHTTPLoopback bool `json:"allow_http_loopback"`

	InstallationID       string `json:"installation_id,omitempty"`
	InstallTokenReadable bool   `json:"install_token_readable"`

	DaemonRunning    bool   `json:"daemon_running"`
	DaemonVersion    string `json:"daemon_version,omitempty"`
	DaemonPID        int    `json:"daemon_pid,omitempty"`
	InstalledVersion string `json:"installed_version,omitempty"`

	HeartbeatAgeSeconds *float64 `json:"heartbeat_age_seconds,omitempty"`
	ExportPending       *int     `json:"export_pending,omitempty"`

	// Warnings mirrors every WARNING line in the text output, so a GUI can show
	// the same findings without parsing prose.
	Warnings []string `json:"warnings"`
}

func PrintStatus(out io.Writer, installedVersion string) DoctorStatus {
	status, _ := Diagnose(out, installedVersion)
	return status
}

// Diagnose runs the same checks as PrintStatus and additionally returns the
// machine-readable report. Pass io.Discard as out for JSON-only callers.
func Diagnose(out io.Writer, installedVersion string) (DoctorStatus, Report) {
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
	// LoadConfig resolves the managed config whose scope drives most of this
	// readout. Defaults to managedconfig.Load; injectable so callers can pin a
	// scope instead of inheriting whatever this machine happens to have under
	// /Library — a real MDM install would otherwise decide the answer.
	LoadConfig func() (managedconfig.LoadedConfig, error)
}

// The returns are NAMED so the deferred summary sync below actually reaches the
// returned Report — with unnamed returns it would mutate a local copy that the
// caller never sees, and every early return would report a zeroed summary.
func printStatus(out io.Writer, installedVersion string, opts doctorOptions) (status DoctorStatus, report Report) {
	status = DoctorStatus{Healthy: true}
	report = Report{InstalledVersion: installedVersion, Warnings: []string{}}
	// warn keeps the text output and the report's Warnings in step: every
	// WARNING a human reads is a warning a GUI can render.
	warn := func(format string, args ...any) {
		message := fmt.Sprintf(format, args...)
		report.Warnings = append(report.Warnings, message)
		fmt.Fprintf(out, "  WARNING: %s\n", message)
	}
	defer func() {
		report.Healthy = status.Healthy
		report.Configured = status.Configured
		report.SelfServe = status.SelfServe
		report.Repairable = status.Repairable
	}()
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
	if opts.LoadConfig == nil {
		opts.LoadConfig = managedconfig.Load
	}

	fmt.Fprintln(out, "Managed observe:")

	// Resolve the active profile FIRST. Path resolution falls back to the legacy
	// paths when the pointer is unreadable, which fails closed but reports as
	// "not configured" — misleading enough to be worth naming explicitly here.
	activeProfile, profileErr := profile.ActiveName()
	switch {
	case profileErr == nil:
		report.ActiveProfile = activeProfile
		fmt.Fprintf(out, "  profile: %s\n", activeProfile)
	case errors.Is(profileErr, profile.ErrNoActive):
		// No pointer means either a pre-profile install or nothing installed at
		// all. Only the former is a "legacy install"; deciding by the pointer
		// alone would label a clean machine as one.
		if legacy := managedconfig.LegacyUserPath(); legacy != "" {
			if _, statErr := os.Lstat(legacy); statErr == nil {
				report.LegacyInstall = true
			}
		}
		if report.LegacyInstall {
			fmt.Fprintln(out, "  profile: none (pre-profile install; `kontext profile migrate` moves it into \"default\")")
		} else {
			fmt.Fprintln(out, "  profile: none")
		}
	default:
		status.Healthy = false
		warn("the active profile pointer is unusable (%v) — config resolution has fallen back to the pre-profile paths; fix or remove %s", profileErr, profile.ActivePath())
	}

	// Through the injected loader, not managedconfig.Load directly: tests pin the
	// scope rather than inheriting whatever this Mac has under /Library.
	loaded, err := opts.LoadConfig()
	if errors.Is(err, managedconfig.ErrNotManaged) {
		fmt.Fprintln(out, "  config: not configured (run `kontext setup` to connect this Mac to a workspace)")
		return status, report
	}
	if err != nil {
		fmt.Fprintf(out, "  config: ERROR %v\n", err)
		status.Healthy = false
		return status, report
	}
	status.Configured = true
	status.SelfServe = loaded.Scope == managedconfig.ScopeUser
	report.ConfigPath = loaded.Path
	report.ConfigScope = string(loaded.Scope)
	report.CloudURL = loaded.Config.CloudURL
	report.Mode = loaded.Config.Mode
	report.AllowHTTPLoopback = loaded.Config.AllowHTTPLoopback

	fmt.Fprintf(out, "  config: %s (%s)\n", loaded.Path, describeScope(loaded.Scope))
	// Plaintext transport is a posture worth stating outright, even though it is
	// bounded to loopback and deliberately opted into — a profile left over from
	// a local-dev session should be obvious, not something to infer from the URL.
	if loaded.Config.AllowHTTPLoopback {
		fmt.Fprintf(out, "  backend: %s (plaintext http to loopback, allowed by this profile)\n", loaded.Config.CloudURL)
	}
	launchAgentPresent := opts.LaunchAgentPresent()
	repairTargetAvailable = runtime.GOOS == "darwin" && loaded.Scope == managedconfig.ScopeUser && launchAgentPresent
	if loaded.Scope == managedconfig.ScopeUser && !launchAgentPresent {
		fmt.Fprintln(out, "  launch agent: missing (run `kontext setup` to restore the background agent)")
		status.Healthy = false
	}

	// The endpoint is running, but on a posture the operator did not choose.
	// Worth a WARNING rather than a status line: the fix is reinstalling a build
	// that is at least as new as the config, and nothing else here hints at it.
	// Unhealthy, and deliberately not repairable — restarting the daemon cannot
	// teach this binary a mode it does not implement, so --fix must not claim it
	// has a repair for this.
	if unsupported := loaded.Config.UnsupportedMode; unsupported != "" {
		fmt.Fprintf(out, "  WARNING: config requests mode %q, which v%s does not implement — running in %q; this binary is older than the install, reinstall to catch up\n",
			unsupported, installedVersion, loaded.Config.Mode)
		status.Healthy = false
	}

	identityPath := installationPathForScope(loaded.Scope)
	if state, err := installation.LoadFile(identityPath); err == nil {
		report.InstallationID = state.InstallationID
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
		report.InstallTokenReadable = true
		fmt.Fprintf(out, "  install token: readable (%s)\n", loaded.Config.Credentials.InstallTokenRef)
	} else {
		warn("install token is not readable (%v) — the agent cannot stream; re-run `kontext setup` or unlock your login keychain", err)
		status.Healthy = false
	}

	if conn, err := opts.Dial("unix", opts.SocketPath, 500*time.Millisecond); err == nil {
		conn.Close()
		report.DaemonRunning = true
		if daemonStatus := LoadDaemonStatus(opts.DBPath); daemonStatus != nil && pidAlive(daemonStatus.PID) {
			report.DaemonVersion = daemonStatus.Version
			report.DaemonPID = daemonStatus.PID
			fmt.Fprintf(out, "  daemon: running (%s, pid %d)\n", describeDaemonBuild(daemonStatus), daemonStatus.PID)
			if reason, stale := daemonSkew(daemonStatus, installedVersion, buildinfo.Revision(), buildinfo.Modified()); stale {
				if repairTargetAvailable {
					warn("%s — run 'kontext doctor --fix' to restart it", reason)
				} else {
					warn("%s — restart it through its managing installation", reason)
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
					warn("daemon version is unknown — it likely predates v%s; run 'kontext doctor --fix' to restart it", installedVersion)
				} else {
					warn("daemon version is unknown — restart it through its managing installation")
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
		ok, age := printHeartbeat(out, state, opts.Now(), warn)
		report.HeartbeatAgeSeconds = age
		if !ok {
			status.Healthy = false
		}
		ok, pending := printExportLag(exportCtx, out, opts.DBPath, state, warn)
		report.ExportPending = pending
		if !ok {
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
				warn("this Mac is organization-managed but a self-serve agent is also installed; run `kontext setup --uninstall` to remove it")
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
			warn("the agent failed to start — %s (%s)", authErr.Message, authErr.At)
		case authErrorKindCorrupt:
			warn("auth breadcrumb is unreadable — %s", authErr.Message)
		default:
			detail := ""
			if authErr.Status > 0 {
				detail = fmt.Sprintf(" (HTTP %d, %s)", authErr.Status, authErr.At)
			}
			warn("hosted ingest is failing — install token rejected%s; run `kontext setup` with a new token from the dashboard", detail)
		}
	}
	// Restarting a stale daemon is safe only when every other prerequisite is
	// healthy and the self-serve LaunchAgent is a verified Darwin repair target.
	status.Repairable = staleDaemon && status.Healthy && repairTargetAvailable
	if staleDaemon {
		status.Healthy = false
	}
	return status, report
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
// breadcrumb reports a live daemon that is no longer skewed from this binary.
// `doctor --fix` uses it so "restarted" is only printed for a verified comeback
// — launchd can accept a kickstart and still have the new daemon exit
// immediately (unreadable token, missing Cellar path).
//
// It reuses daemonSkew rather than comparing versions directly so that "came
// back" means the same thing here as "up to date" does in the readout above. It
// also narrows a hole: on builds that share a version string (notably `dev`) the
// old version comparison accepted ANY live daemon, so a daemon that never
// restarted was reported as restarted. Stamped builds now have to match by
// revision. Two dirty builds of one commit remain indistinguishable, so a
// modified local build can still satisfy this without having restarted —
// unavoidable from the stamp alone, and never the case for a release build.
func WaitForDaemonRestart(ctx context.Context, dbPath, socketPath, wantVersion string) (*DaemonStatus, error) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	installedRevision := buildinfo.Revision()
	installedModified := buildinfo.Modified()
	for {
		if conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond); err == nil {
			conn.Close()
			if status := LoadDaemonStatus(dbPath); status != nil && pidAlive(status.PID) {
				if _, stale := daemonSkew(status, wantVersion, installedRevision, installedModified); !stale {
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

// describeDaemonBuild renders the running daemon's identity, including the
// source revision when the daemon recorded one. Older daemons wrote no revision
// and still print exactly as they used to.
func describeDaemonBuild(status *DaemonStatus) string {
	build := "v" + status.Version
	if revision := buildinfo.DescribeRevision(status.Revision, status.Modified); revision != "" {
		build += " " + revision
	}
	return build
}

// daemonSkew decides whether the running daemon is a different build from the
// installed binary, preferring evidence over labels.
//
// REVISION FIRST, when both sides have one: it is the only field that identifies
// a build. A version string is injected at link time, so a channel that labels
// builds by date can hand two different sources the same version — or, for local
// and unlabeled builds, hand every source the same "dev" — and a version
// comparison then reports a match that is not one.
//
// Version is the fallback for daemons that predate the revision breadcrumb.
// A missing revision on either side is NOT treated as a mismatch: unstamped
// builds are legitimate, and warning on them would make the check unusable for
// everyone who builds with -buildvcs=false.
//
// Equal revisions prove equal source only for CLEAN builds. With a modified tree
// on either side the revision names the commit that build was based on, not what
// was compiled, so equality is unproven rather than established — two different
// dirty builds of one commit look identical here. That stays quiet on purpose:
// nothing in the stamp can tell those apart (the toolchain records no content
// hash), and a warning would then fire on every local build and make `doctor
// --fix` unable to ever verify a restart. The readout marks such builds
// "+modified" so the reader can see the match is approximate. Release builds are
// never modified, so this costs the production path nothing.
func daemonSkew(status *DaemonStatus, installedVersion, installedRevision string, installedModified bool) (string, bool) {
	daemonRevision := strings.TrimSpace(status.Revision)
	installedRevision = strings.TrimSpace(installedRevision)
	if daemonRevision != "" && installedRevision != "" {
		if daemonRevision == installedRevision {
			return "", false
		}
		installed := "v" + installedVersion
		if short := buildinfo.DescribeRevision(installedRevision, installedModified); short != "" {
			installed += " " + short
		}
		return fmt.Sprintf("daemon is running build %s but %s is installed",
			describeDaemonBuild(status), installed), true
	}

	if comparableVersion(status.Version) && comparableVersion(installedVersion) && status.Version != installedVersion {
		return fmt.Sprintf("daemon is running v%s but v%s is installed", status.Version, installedVersion), true
	}
	return "", false
}

// printHeartbeat reports the daemon's last healthy beat, returning whether it is
// acceptable and its age in seconds (nil when there is nothing to measure).
func printHeartbeat(out io.Writer, state managedstream.State, now time.Time, warn func(string, ...any)) (bool, *float64) {
	if strings.TrimSpace(state.LastHeartbeatAt) == "" {
		fmt.Fprintln(out, "  heartbeat: none recorded yet (the daemon has not reported healthy)")
		return false, nil
	}
	last, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(state.LastHeartbeatAt))
	if err != nil {
		fmt.Fprintln(out, "  heartbeat: ERROR invalid timestamp")
		return false, nil
	}
	age := now.Sub(last)
	if age < 0 {
		age = 0
	}
	seconds := age.Seconds()
	fmt.Fprintf(out, "  heartbeat: %s ago\n", doctorDuration(age))
	if age > 5*time.Minute {
		warn("last heartbeat was %s ago — the daemon may be stalled", doctorDuration(age))
		return false, &seconds
	}
	return true, &seconds
}

// printExportLag reports the export backlog, returning whether it is acceptable
// and how many events are pending (nil when the ledger could not be read).
func printExportLag(ctx context.Context, out io.Writer, dbPath string, state managedstream.State, warn func(string, ...any)) (bool, *int) {
	var cursor *sqlite.LedgerCursor
	if state.UpdatedAfter != nil {
		cursor = &sqlite.LedgerCursor{UpdatedAt: *state.UpdatedAfter, ActionID: state.ActionID}
	}
	newest, pending, err := sqlite.LedgerLag(ctx, dbPath, cursor)
	if err != nil {
		fmt.Fprintf(out, "  export: ERROR %v\n", err)
		return false, nil
	}
	if newest == nil {
		fmt.Fprintln(out, "  export: no ledger events yet")
		return true, &pending
	}
	if cursor == nil {
		fmt.Fprintf(out, "  export: not started yet (%d pending)\n", pending)
		return false, &pending
	}
	lag := newest.Sub(cursor.UpdatedAt)
	if lag < 0 {
		lag = 0
	}
	// The export cursor rides 30s behind newest by design (cursorSafetyLag),
	// hence the 10m warning threshold.
	if lag > 10*time.Minute && pending > 0 {
		warn("export lagging %s (%d events pending) — the daemon may be stalled", doctorDuration(lag), pending)
		return false, &pending
	}
	if pending == 0 {
		fmt.Fprintln(out, "  export: up to date (0 pending)")
		return true, &pending
	}
	// Never claim "up to date" while rows are waiting — report the facts and
	// let the operator judge.
	fmt.Fprintf(out, "  export: %d pending (cursor %s behind newest)\n", pending, doctorDuration(lag))
	return true, &pending
}

func doctorDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	return d.Round(time.Minute).String()
}

// DaemonLive reports whether a daemon serving THIS database is actually running.
//
// A reachable socket is not sufficient evidence on its own: the socket path is
// shared across installations, so an unrelated daemon — a leftover from an
// enterprise package, or one started by hand — binds the same path and answers.
// The status breadcrumb is written beside the database the daemon is serving, so
// checking it for a live pid ties the answer to the intended install rather than
// to whoever holds the socket.
//
// A daemon predating the breadcrumb reads as not-live. That is the harmless
// direction: the caller restarts an already-current daemon.
func DaemonLive(dbPath, socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	status := LoadDaemonStatus(dbPath)
	return status != nil && pidAlive(status.PID)
}
