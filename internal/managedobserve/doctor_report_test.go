package managedobserve

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/kontext-security/kontext-cli/internal/managedconfig"
	"github.com/kontext-security/kontext-cli/internal/profile"
)

// The report's summary flags are filled in by a deferred assignment. With
// unnamed return values that defer would mutate a local copy and every caller
// would see a zeroed summary, so pin the behavior — including on the early
// returns, which is where it would break first.
func TestDiagnoseReportCarriesSummaryFlags(t *testing.T) {
	env := newDoctorTestEnv(t)
	t.Setenv(profile.EnvRoot, "")
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")

	var out bytes.Buffer
	status, report := printStatus(&out, "1.2.3", env.options())

	if report.Configured != status.Configured {
		t.Errorf("report.Configured = %v, want %v", report.Configured, status.Configured)
	}
	if report.Healthy != status.Healthy {
		t.Errorf("report.Healthy = %v, want %v", report.Healthy, status.Healthy)
	}
	if report.SelfServe != status.SelfServe {
		t.Errorf("report.SelfServe = %v, want %v", report.SelfServe, status.SelfServe)
	}
	if report.Repairable != status.Repairable {
		t.Errorf("report.Repairable = %v, want %v", report.Repairable, status.Repairable)
	}
	if !report.Configured {
		t.Fatal("expected the test env to be configured; the assertions above are vacuous otherwise")
	}
	if report.InstalledVersion != "1.2.3" {
		t.Errorf("InstalledVersion = %q, want 1.2.3", report.InstalledVersion)
	}
	if report.ConfigPath == "" {
		t.Error("ConfigPath is empty")
	}
	if report.InstallationID == "" {
		t.Error("InstallationID is empty")
	}
}

// The early return taken when nothing is configured must still carry the
// summary flags.
func TestDiagnoseReportSummaryOnUnconfiguredEarlyReturn(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv(profile.EnvRoot, root)
	var out bytes.Buffer
	// Pin the resolution instead of leaving it to this machine: unset config
	// falls through to the SYSTEM path, so an enterprise install would otherwise
	// decide the answer and this would stop testing the unconfigured case.
	status, report := printStatus(&out, "1.2.3", doctorOptions{
		LoadConfig: func() (managedconfig.LoadedConfig, error) {
			return managedconfig.LoadedConfig{}, managedconfig.ErrNotManaged
		},
	})

	if report.Configured {
		t.Error("Configured = true on an unconfigured machine")
	}
	if report.Healthy != status.Healthy {
		t.Errorf("report.Healthy = %v, want %v", report.Healthy, status.Healthy)
	}
	// Warnings must be a usable empty slice, not a nil that marshals to null.
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"warnings":[]`) {
		t.Errorf("warnings did not marshal as an empty array: %s", data)
	}
}

// A machine with nothing installed is not a "legacy install" — deciding by the
// absent pointer alone would mislabel a clean machine.
func TestDiagnoseDoesNotCallCleanMachineLegacy(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv(profile.EnvRoot, root)
	var out bytes.Buffer
	_, report := printStatus(&out, "1.2.3", doctorOptions{
		LoadConfig: func() (managedconfig.LoadedConfig, error) {
			return managedconfig.LoadedConfig{}, managedconfig.ErrNotManaged
		},
	})

	if report.LegacyInstall {
		t.Error("LegacyInstall = true on a machine with nothing installed")
	}
	if report.ActiveProfile != "" {
		t.Errorf("ActiveProfile = %q, want empty", report.ActiveProfile)
	}
}

func TestDiagnoseReportsLegacyInstall(t *testing.T) {
	env := newDoctorTestEnv(t)
	t.Setenv(profile.EnvRoot, "")

	var out bytes.Buffer
	_, report := printStatus(&out, "1.2.3", env.options())

	// newDoctorTestEnv writes a config at the legacy path and no pointer.
	if !report.LegacyInstall {
		t.Error("LegacyInstall = false, want true for an unprofiled install")
	}
	if !strings.Contains(out.String(), "profile: none") {
		t.Errorf("output does not report the profile state:\n%s", out.String())
	}
}

func TestDiagnoseReportsActiveProfile(t *testing.T) {
	env := newDoctorTestEnv(t)
	t.Setenv(profile.EnvRoot, "")
	if _, err := profile.Create("staging"); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetActive("staging"); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	_, report := printStatus(&out, "1.2.3", env.options())

	if report.ActiveProfile != "staging" {
		t.Errorf("ActiveProfile = %q, want staging", report.ActiveProfile)
	}
	if report.LegacyInstall {
		t.Error("LegacyInstall = true while a profile is active")
	}
	if !strings.Contains(out.String(), "profile: staging") {
		t.Errorf("output does not name the active profile:\n%s", out.String())
	}
}

// A corrupt pointer makes path resolution fall back to the legacy paths, which
// fails closed but otherwise reads as "not configured". Doctor must name the
// real cause.
func TestDiagnoseWarnsAboutUnusableProfilePointer(t *testing.T) {
	env := newDoctorTestEnv(t)
	t.Setenv(profile.EnvRoot, "")
	if err := os.WriteFile(profile.ActivePath(), []byte("../../elsewhere\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	status, report := printStatus(&out, "1.2.3", env.options())

	if status.Healthy {
		t.Error("Healthy = true with an unusable profile pointer")
	}
	var found bool
	for _, warning := range report.Warnings {
		if strings.Contains(warning, "active profile pointer is unusable") {
			found = true
		}
	}
	if !found {
		t.Errorf("no pointer warning in report.Warnings = %v", report.Warnings)
	}
	if !strings.Contains(out.String(), "WARNING: the active profile pointer is unusable") {
		t.Errorf("text output omits the pointer warning:\n%s", out.String())
	}
}

// Every WARNING a human reads must appear in the report, so a GUI shows the
// same findings without parsing prose.
func TestDiagnoseWarningsMirrorTextOutput(t *testing.T) {
	env := newDoctorTestEnv(t)
	t.Setenv(profile.EnvRoot, "")
	// A daemon on a different version than installed produces a stale-daemon
	// warning.
	env.writeDaemonStatus(t, os.Getpid(), "1.0.0")

	var out bytes.Buffer
	_, report := printStatus(&out, "1.2.3", env.options())

	textWarnings := 0
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "WARNING: ") {
			textWarnings++
		}
	}
	if textWarnings == 0 {
		t.Fatalf("expected at least one warning in:\n%s", out.String())
	}
	if len(report.Warnings) != textWarnings {
		t.Errorf("report has %d warnings but text has %d:\nreport: %v\ntext:\n%s",
			len(report.Warnings), textWarnings, report.Warnings, out.String())
	}
	for _, warning := range report.Warnings {
		if !strings.Contains(out.String(), "WARNING: "+warning) {
			t.Errorf("report warning %q does not appear verbatim in the text output", warning)
		}
	}
}

func TestDiagnoseReportRecordsDaemonAndExportState(t *testing.T) {
	env := newDoctorTestEnv(t)
	t.Setenv(profile.EnvRoot, "")
	env.writeDaemonStatus(t, os.Getpid(), "1.2.3")

	var out bytes.Buffer
	_, report := printStatus(&out, "1.2.3", env.options())

	if !report.DaemonRunning {
		t.Error("DaemonRunning = false, want true")
	}
	if report.DaemonVersion != "1.2.3" {
		t.Errorf("DaemonVersion = %q, want 1.2.3", report.DaemonVersion)
	}
	if report.DaemonPID != os.Getpid() {
		t.Errorf("DaemonPID = %d, want %d", report.DaemonPID, os.Getpid())
	}
	if report.HeartbeatAgeSeconds == nil {
		t.Error("HeartbeatAgeSeconds is nil despite a recorded heartbeat")
	} else if *report.HeartbeatAgeSeconds != 20 {
		t.Errorf("HeartbeatAgeSeconds = %v, want 20", *report.HeartbeatAgeSeconds)
	}
}
