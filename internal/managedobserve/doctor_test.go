package managedobserve

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext-cli/internal/guard/risk"
	sqlitestore "github.com/kontext-security/kontext-cli/internal/guard/store/sqlite"
	"github.com/kontext-security/kontext-cli/internal/installation"
	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/managedstream"
)

func TestPrintStatusReportsInstallationLoadError(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "managed.json")
	installationPath := filepath.Join(dir, "installation.json")

	writeTestManagedConfig(t, configPath)
	if err := os.WriteFile(installationPath, []byte(`{"installation_id":`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managedconfig.EnvPath, configPath)
	t.Setenv(installation.EnvPath, installationPath)
	t.Setenv("KONTEXT_INSTALL_TOKEN", "test-install-token")

	var out bytes.Buffer
	PrintStatus(&out, "1.2.3")
	output := out.String()
	if !strings.Contains(output, "installation: ERROR") {
		t.Fatalf("PrintStatus() output = %q, want installation error", output)
	}
	if strings.Contains(output, "installation: not created yet") {
		t.Fatalf("PrintStatus() output = %q, must not hide invalid state as missing", output)
	}
	if strings.Contains(output, "\n  organization:") {
		t.Fatalf("PrintStatus() output = %q, must not print local organization", output)
	}
}

// A downgraded endpoint still loads, so the only thing standing between the
// operator and a silently wrong posture is this warning.
func TestPrintStatusWarnsOnUnsupportedConfigMode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "managed.json")
	writeTestManagedConfig(t, configPath)
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	degraded := strings.Replace(string(config), `"mode": "observe"`, `"mode": "some-future-posture"`, 1)
	if err := os.WriteFile(configPath, []byte(degraded), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	status := PrintStatus(&out, "1.2.3")
	output := out.String()
	if !strings.Contains(output, `WARNING: config requests mode "some-future-posture"`) {
		t.Fatalf("PrintStatus() output = %q, want unsupported mode warning", output)
	}
	if strings.Contains(output, "config: ERROR") {
		t.Fatalf("PrintStatus() output = %q, an unsupported mode must not read as an unloadable config", output)
	}
	if status.Healthy {
		t.Fatal("PrintStatus() reported healthy while running a posture the operator did not choose")
	}
	// Reinstalling is the only fix; --fix must not offer a daemon restart that
	// cannot possibly help.
	if status.Repairable {
		t.Fatal("PrintStatus() reported a downgraded endpoint as repairable")
	}
}

// The complement: a healthy install must stay quiet, or the warning is noise.
func TestPrintStatusDoesNotWarnOnSupportedConfigMode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "managed.json")
	writeTestManagedConfig(t, configPath)

	var out bytes.Buffer
	PrintStatus(&out, "1.2.3")
	if output := out.String(); strings.Contains(output, "config requests mode") {
		t.Fatalf("PrintStatus() output = %q, want no unsupported mode warning", output)
	}
}

// The identity check this whole breadcrumb exists for. Table-driven because the
// interesting behavior is entirely in which signal wins.
func TestDaemonSkew(t *testing.T) {
	const revisionA = "cac15fd669a7e4b0bfbdd78413d25fc0999e3a11"
	const revisionB = "f7be605aaaa1111bbbb2222cccc3333dddd4444e"

	for name, test := range map[string]struct {
		status            DaemonStatus
		installedVersion  string
		installedRevision string
		installedModified bool
		wantStale         bool
		wantContains      string
	}{
		"same revision is not skew even when versions differ": {
			// A rebuild of one source can be labeled twice. The source is what
			// matters, so this must stay quiet.
			status:            DaemonStatus{Version: "0.0.0-staging.20260730.9", Revision: revisionA},
			installedVersion:  "0.0.0-staging.20260731.15",
			installedRevision: revisionA,
			wantStale:         false,
		},
		"different revision is skew even when versions match": {
			// The case a version comparison cannot see: two builds sharing a
			// label. Date-stamped channels and "dev" both produce it.
			status:            DaemonStatus{Version: "dev", Revision: revisionA},
			installedVersion:  "dev",
			installedRevision: revisionB,
			wantStale:         true,
			wantContains:      "daemon is running build vdev cac15fd6 but vdev f7be605a is installed",
		},
		"falls back to version when the daemon predates the revision field": {
			status:            DaemonStatus{Version: "0.14.1"},
			installedVersion:  "0.16.0",
			installedRevision: revisionB,
			wantStale:         true,
			wantContains:      "daemon is running v0.14.1 but v0.16.0 is installed",
		},
		"unstamped installed binary still compares versions": {
			status:            DaemonStatus{Version: "0.14.1", Revision: revisionA},
			installedVersion:  "0.16.0",
			installedRevision: "",
			wantStale:         true,
			wantContains:      "daemon is running v0.14.1 but v0.16.0 is installed",
		},
		// Warning on a missing stamp would make the check unusable for anyone
		// building with -buildvcs=false.
		"no revisions and equal versions is not skew": {
			status:           DaemonStatus{Version: "0.16.0"},
			installedVersion: "0.16.0",
			wantStale:        false,
		},
		"dev builds with no stamps stay quiet": {
			status:           DaemonStatus{Version: "dev"},
			installedVersion: "dev",
			wantStale:        false,
		},
		// A dirty tree makes equality unprovable, not false. Warning here would
		// fire on every local build and leave `doctor --fix` unable to verify a
		// restart, so it stays quiet and the readout marks it "+modified".
		"same revision from modified trees is unproven, not skew": {
			status:            DaemonStatus{Version: "dev", Revision: revisionA, Modified: true},
			installedVersion:  "dev",
			installedRevision: revisionA,
			installedModified: true,
			wantStale:         false,
		},
		// Different revisions are still conclusive whatever the tree state, and
		// the message must show which side is not a clean build.
		"different revisions from modified trees are still skew": {
			status:            DaemonStatus{Version: "dev", Revision: revisionA, Modified: true},
			installedVersion:  "dev",
			installedRevision: revisionB,
			installedModified: true,
			wantStale:         true,
			wantContains:      "daemon is running build vdev cac15fd6+modified but vdev f7be605a+modified is installed",
		},
	} {
		t.Run(name, func(t *testing.T) {
			status := test.status
			reason, stale := daemonSkew(&status, test.installedVersion, test.installedRevision, test.installedModified)
			if stale != test.wantStale {
				t.Fatalf("daemonSkew() stale = %v, want %v (reason %q)", stale, test.wantStale, reason)
			}
			if test.wantContains != "" && !strings.Contains(reason, test.wantContains) {
				t.Fatalf("daemonSkew() reason = %q, want it to contain %q", reason, test.wantContains)
			}
		})
	}
}

func TestDescribeDaemonBuildIncludesRevisionWhenRecorded(t *testing.T) {
	withRevision := DaemonStatus{Version: "0.14.1", Revision: "cac15fd669a7e4b0bfbdd78413d25fc0999e3a11"}
	if got, want := describeDaemonBuild(&withRevision), "v0.14.1 cac15fd6"; got != want {
		t.Fatalf("describeDaemonBuild() = %q, want %q", got, want)
	}
	// A daemon built from a dirty tree must not read as an exact build: this is
	// the reader's only cue that comparing it to the installed binary is
	// approximate.
	modified := DaemonStatus{Version: "0.14.1", Revision: "cac15fd669a7e4b0bfbdd78413d25fc0999e3a11", Modified: true}
	if got, want := describeDaemonBuild(&modified), "v0.14.1 cac15fd6+modified"; got != want {
		t.Fatalf("describeDaemonBuild() = %q, want %q", got, want)
	}
	// Daemons started before the field existed must render exactly as before.
	legacy := DaemonStatus{Version: "0.14.1"}
	if got, want := describeDaemonBuild(&legacy), "v0.14.1"; got != want {
		t.Fatalf("describeDaemonBuild() = %q, want %q", got, want)
	}
}

func TestPrintStatusDaemonVersionMatch(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")

	var out bytes.Buffer
	status, _ := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if !status.Healthy || status.Repairable {
		t.Fatalf("status = %+v, want healthy and not repairable", status)
	}
	if !strings.Contains(output, "  daemon: running (v1.2.3, pid ") {
		t.Fatalf("output = %q, want daemon version and pid", output)
	}
	if strings.Contains(output, "WARNING: daemon is running") {
		t.Fatalf("output = %q, want no version warning", output)
	}
}

func TestPrintStatusDaemonVersionMismatch(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.2")

	var out bytes.Buffer
	status, _ := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if status.Healthy || status.Repairable != wantAutomaticDaemonRepair() {
		t.Fatalf("status = %+v, want unhealthy and repairable=%v", status, wantAutomaticDaemonRepair())
	}
	if !strings.Contains(output, "WARNING: daemon is running v1.2.2 but v1.2.3 is installed") {
		t.Fatalf("output = %q, want mismatch warning", output)
	}
}

func TestPrintStatusDaemonDevVersionDoesNotWarn(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "dev")

	var out bytes.Buffer
	status, _ := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if !status.Healthy || status.Repairable {
		t.Fatalf("status = %+v, want healthy and not repairable", status)
	}
	if strings.Contains(output, "WARNING: daemon is running") {
		t.Fatalf("output = %q, want no dev mismatch warning", output)
	}
}

func TestPrintStatusDaemonDeadPIDTreatedAsUnknownAndFixable(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, deadPID(t), "1.2.2")

	var out bytes.Buffer
	status, _ := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if status.Healthy || status.Repairable != wantAutomaticDaemonRepair() {
		t.Fatalf("status = %+v, want unhealthy and repairable=%v", status, wantAutomaticDaemonRepair())
	}
	if !strings.Contains(output, "  daemon: running\n") {
		t.Fatalf("output = %q, want plain running line", output)
	}
	if strings.Contains(output, "pid ") {
		t.Fatalf("output = %q, want no dead-pid status details", output)
	}
	if !strings.Contains(output, "WARNING: daemon version is unknown") {
		t.Fatalf("output = %q, want unknown-version warning", output)
	}
}

func TestPIDAliveRejectsNonPositivePID(t *testing.T) {
	for _, pid := range []int{0, -1} {
		if pidAlive(pid) {
			t.Fatalf("pidAlive(%d) = true, want false", pid)
		}
	}
}

func TestPrintStatusDaemonWithoutBreadcrumbIsFixable(t *testing.T) {
	// A serving daemon that never wrote daemon-status.json predates the
	// breadcrumb feature — the first-upgrade case doctor --fix must handle.
	env := newDoctorTestEnv(t)

	var out bytes.Buffer
	status, _ := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if status.Healthy || status.Repairable != wantAutomaticDaemonRepair() {
		t.Fatalf("status = %+v, want unhealthy and repairable=%v", status, wantAutomaticDaemonRepair())
	}
	wantWarning := "WARNING: daemon version is unknown — it likely predates v1.2.3"
	if !wantAutomaticDaemonRepair() {
		wantWarning = "WARNING: daemon version is unknown — restart it through its managing installation"
	}
	if !strings.Contains(output, wantWarning) {
		t.Fatalf("output = %q, want warning %q", output, wantWarning)
	}
}

func TestPrintStatusDaemonWithoutBreadcrumbDevInstallDoesNotWarn(t *testing.T) {
	env := newDoctorTestEnv(t)

	var out bytes.Buffer
	status, _ := printStatus(&out, "dev", env.options())

	output := out.String()
	if !status.Healthy || status.Repairable {
		t.Fatalf("status = %+v, want healthy and not repairable", status)
	}
	if strings.Contains(output, "WARNING: daemon version is unknown") {
		t.Fatalf("output = %q, want no warning for dev install", output)
	}
}

func TestPrintStatusHeartbeatFreshAndExportUpToDate(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")
	cursor := env.seedLedger(t)
	if err := managedstream.SaveState(managedstream.DefaultStatePathForDB(env.dbPath), managedstream.State{
		UpdatedAfter:    &cursor.UpdatedAt,
		ActionID:        cursor.ActionID,
		LastHeartbeatAt: env.now.Add(-20 * time.Second).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	status, _ := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if !status.Healthy || status.Repairable {
		t.Fatalf("status = %+v, want healthy and not repairable", status)
	}
	if !strings.Contains(output, "  heartbeat: 20s ago") {
		t.Fatalf("output = %q, want fresh heartbeat", output)
	}
	if !strings.Contains(output, "  export: up to date (0 pending)") {
		t.Fatalf("output = %q, want export up to date", output)
	}
}

func TestPrintStatusHeartbeatOldAndExportLagging(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")
	env.seedLedger(t)
	updatedAfter := time.Unix(0, 0).UTC()
	if err := managedstream.SaveState(managedstream.DefaultStatePathForDB(env.dbPath), managedstream.State{
		UpdatedAfter:    &updatedAfter,
		LastHeartbeatAt: env.now.Add(-6 * time.Minute).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	status, _ := printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if status.Healthy || status.Repairable {
		t.Fatalf("status = %+v, want unhealthy and not repairable", status)
	}
	if !strings.Contains(output, "WARNING: last heartbeat was 6m0s ago") {
		t.Fatalf("output = %q, want old heartbeat warning", output)
	}
	if !strings.Contains(output, "WARNING: export lagging") || !strings.Contains(output, "events pending") {
		t.Fatalf("output = %q, want export lag warning", output)
	}
}

func TestPrintStatusExportPendingWithinThresholdReportsFacts(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")
	env.seedLedger(t)
	// Cursor a minute behind the just-seeded event: pending but not lagging.
	updatedAfter := time.Now().UTC().Add(-time.Minute)
	if err := managedstream.SaveState(managedstream.DefaultStatePathForDB(env.dbPath), managedstream.State{
		UpdatedAfter:    &updatedAfter,
		LastHeartbeatAt: env.now.Add(-20 * time.Second).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	printStatus(&out, "1.2.3", env.options())

	output := out.String()
	if !strings.Contains(output, "pending (cursor ") {
		t.Fatalf("output = %q, want pending facts line", output)
	}
	if strings.Contains(output, "export: up to date") {
		t.Fatalf("output = %q, want no up-to-date claim while rows are pending", output)
	}
	if strings.Contains(output, "WARNING: export lagging") {
		t.Fatalf("output = %q, want no lag warning under threshold", output)
	}
}

func TestWaitForDaemonRestartSucceeds(t *testing.T) {
	env := newDoctorTestEnv(t)
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")
	// Unix socket paths cap at 104 bytes on macOS; t.TempDir is too deep.
	socketDir, err := os.MkdirTemp("/tmp", "kontext-doctor-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp() error = %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "kontext.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, err := WaitForDaemonRestart(ctx, env.dbPath, socketPath, "1.2.3")
	if err != nil {
		t.Fatalf("WaitForDaemonRestart() error = %v", err)
	}
	if status.Version != "1.2.3" || status.PID != os.Getpid() {
		t.Fatalf("status = %+v, want current pid on v1.2.3", status)
	}
}

func TestWaitForDaemonRestartTimesOutWithoutDaemon(t *testing.T) {
	env := newDoctorTestEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := WaitForDaemonRestart(ctx, env.dbPath, env.socketPath, "1.2.3"); err == nil {
		t.Fatal("WaitForDaemonRestart() error = nil, want timeout")
	}
}

// Config scope decides the org-managed callout, and it must come from the
// injected loader — not from whatever managed.json this Mac happens to have
// under /Library. Before doctorOptions.LoadConfig existed, a developer with the
// customer .pkg installed silently ran every doctor test at system scope and
// saw this warning flip them all red.
func TestPrintStatusOrgManagedWarningFollowsConfigScope(t *testing.T) {
	const orgManagedWarning = "WARNING: this Mac is organization-managed but a self-serve agent is also installed"

	// Everything except scope is healthy, so scope is the only thing that can
	// move Healthy.
	newHealthyEnv := func(t *testing.T) doctorTestEnv {
		t.Helper()
		env := newDoctorTestEnv(t)
		env.writeDaemonStatus(t, os.Getpid(), "1.2.3")
		cursor := env.seedLedger(t)
		if err := managedstream.SaveState(managedstream.DefaultStatePathForDB(env.dbPath), managedstream.State{
			UpdatedAfter:    &cursor.UpdatedAt,
			ActionID:        cursor.ActionID,
			LastHeartbeatAt: env.now.Add(-20 * time.Second).Format(time.RFC3339Nano),
		}); err != nil {
			t.Fatal(err)
		}
		return env
	}

	t.Run("user scope is a plain self-serve install", func(t *testing.T) {
		env := newHealthyEnv(t)

		var out bytes.Buffer
		status, _ := printStatus(&out, "1.2.3", env.options())

		output := out.String()
		if !status.Healthy || !status.SelfServe {
			t.Fatalf("status = %+v, want healthy and self-serve; output = %q", status, output)
		}
		if strings.Contains(output, orgManagedWarning) {
			t.Fatalf("output = %q, want no org-managed warning at user scope", output)
		}
	})

	t.Run("system scope plus a user agent is a conflict", func(t *testing.T) {
		env := newHealthyEnv(t)
		opts := env.options()
		opts.LoadConfig = env.loadConfig(managedconfig.ScopeSystem)

		var out bytes.Buffer
		status, _ := printStatus(&out, "1.2.3", opts)

		output := out.String()
		if status.Healthy || status.SelfServe {
			t.Fatalf("status = %+v, want unhealthy and not self-serve; output = %q", status, output)
		}
		if !strings.Contains(output, orgManagedWarning) {
			t.Fatalf("output = %q, want warning %q", output, orgManagedWarning)
		}
	})
}

type doctorTestEnv struct {
	dir        string
	dbPath     string
	socketPath string
	configPath string
	now        time.Time
}

func wantAutomaticDaemonRepair() bool {
	return runtime.GOOS == "darwin"
}

func newDoctorTestEnv(t *testing.T) doctorTestEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	configPath := filepath.Join(dir, "Library", "Application Support", "Kontext", "managed.json")
	installationPath := filepath.Join(dir, "installation.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestManagedConfig(t, configPath)
	t.Setenv(managedconfig.EnvPath, "")
	writeTestInstallation(t, installationPath)
	t.Setenv(installation.EnvPath, installationPath)
	if err := managedstream.SaveState(managedstream.DefaultStatePathForDB(filepath.Join(dir, "guard.db")), managedstream.State{
		LastHeartbeatAt: time.Date(2026, 7, 9, 11, 59, 40, 0, time.UTC).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	return doctorTestEnv{
		dir:        dir,
		dbPath:     filepath.Join(dir, "guard.db"),
		socketPath: filepath.Join(dir, "kontext.sock"),
		configPath: configPath,
		now:        time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC),
	}
}

// loadConfig reads this env's fixture at a caller-chosen scope. Tests must not
// go through managedconfig.ResolvePath: it prefers an existing system config,
// so on any Mac with a real pkg install the fixture would lose to
// /Library/Application Support/Kontext/managed.json.
func (e doctorTestEnv) loadConfig(scope managedconfig.Scope) func() (managedconfig.LoadedConfig, error) {
	return func() (managedconfig.LoadedConfig, error) {
		loaded, err := managedconfig.LoadFile(e.configPath)
		if err != nil {
			return managedconfig.LoadedConfig{}, err
		}
		loaded.Scope = scope
		return loaded, nil
	}
}

func (e doctorTestEnv) options() doctorOptions {
	return doctorOptions{
		DBPath:     e.dbPath,
		SocketPath: e.socketPath,
		Dial: func(string, string, time.Duration) (net.Conn, error) {
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
		Now:                func() time.Time { return e.now },
		LaunchAgentPresent: func() bool { return true },
		LoadConfig:         e.loadConfig(managedconfig.ScopeUser),
	}
}

func (e doctorTestEnv) writeDaemonStatus(t *testing.T, pid int, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(DaemonStatusPath(e.dbPath)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONBreadcrumb(DaemonStatusPath(e.dbPath), DaemonStatus{
		Version:   version,
		PID:       pid,
		StartedAt: "2026-07-09T12:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
}

func (e doctorTestEnv) seedLedger(t *testing.T) *sqlitestore.LedgerCursor {
	t.Helper()
	store, err := sqlitestore.OpenStore(e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.SaveDecision(context.Background(), risk.HookEvent{
		SessionID:     "s1",
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolUseID:     "tool-1",
	}, risk.RiskDecision{
		Decision:   risk.DecisionAllow,
		Reason:     "ok",
		ReasonCode: "normal_tool_call",
		RiskEvent:  risk.RiskEvent{Type: risk.EventNormalToolCall},
	}); err != nil {
		t.Fatal(err)
	}
	batch, err := store.LedgerBatch(context.Background(), sqlitestore.LedgerExportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if batch.Cursor == nil {
		t.Fatal("LedgerBatch cursor = nil")
	}
	return batch.Cursor
}

func deadPID(t *testing.T) int {
	t.Helper()
	for pid := os.Getpid() + 100000; pid < os.Getpid()+101000; pid++ {
		if !pidAlive(pid) {
			return pid
		}
	}
	t.Fatal("could not find a dead pid")
	return 0
}
