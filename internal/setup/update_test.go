package setup

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/autostart"
	"github.com/kontext-security/kontext/internal/managedobserve"
)

// updateRun is a user's install and a newer release beside it, with the
// session's seams faked, on any OS.
type updateRun struct {
	install, release string
	status           *managedobserve.DaemonStatus
	stops            []string
	starts           int
	// startedVersion is what an agent started by the update reports.
	startedVersion string
	// renameFails makes the rename onto this path fail.
	renameFails string
}

func newUpdateRun(t *testing.T) *updateRun {
	t.Helper()
	root := t.TempDir()
	run := &updateRun{
		install:        filepath.Join(root, "Programs", "Kontext"),
		release:        filepath.Join(root, "Downloads", "kontext_9.9.9_windows_amd64"),
		status:         &managedobserve.DaemonStatus{Version: "1.0.0", PID: 100},
		startedVersion: "9.9.9",
	}
	for dir, content := range map[string]string{run.install: "old", run.release: "new"} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range updatePrograms {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content+" "+name), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	overrideVar(t, &goos, "windows")
	overrideVar(t, &systemConfigPath, filepath.Join(root, "ProgramData", "Kontext", "managed.json"))
	overrideVar(t, &executablePath, func() (string, error) { return filepath.Join(run.release, "kontext.exe"), nil })
	overrideVar(t, &readWindowsAutostart, func() (string, error) {
		return autostart.Command(filepath.Join(run.install, windowsDaemonName)), nil
	})
	overrideVar(t, &loadDaemonStatus, func() *managedobserve.DaemonStatus {
		if run.status == nil {
			return nil
		}
		copied := *run.status
		return &copied
	})
	overrideVar(t, &stopWindowsDaemon, func(program string) (bool, error) {
		run.stops = append(run.stops, program)
		return true, nil
	})
	overrideVar(t, &startWindowsDaemon, func(program string, args ...string) error {
		run.starts++
		run.status = &managedobserve.DaemonStatus{Version: run.startedVersion, PID: 100 + run.starts}
		return nil
	})
	overrideVar(t, &renameFile, func(from, to string) error {
		if run.renameFails != "" && to == run.renameFails {
			return errors.New("access is denied")
		}
		return os.Rename(from, to)
	})
	overrideVar(t, &daemonStartWait, 200*time.Millisecond)
	overrideVar(t, &updateStatusEvery, 10*time.Millisecond)
	return run
}

func (r *updateRun) content(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(r.install, name))
	if err != nil {
		return "missing"
	}
	return string(data)
}

func TestUpdatePutsTheReleaseInPlaceAndChecksTheNewAgent(t *testing.T) {
	run := newUpdateRun(t)
	var out bytes.Buffer
	if err := Update(context.Background(), UpdateOptions{Version: "9.9.9", Stdout: &out}); err != nil {
		t.Fatalf("Update: %v\n%s", err, out.String())
	}
	for _, name := range updatePrograms {
		if got := run.content(t, name); got != "new "+name {
			t.Errorf("%s = %q, want the release's", name, got)
		}
		if got := run.content(t, name+".old"); got != "old "+name {
			t.Errorf("%s.old = %q, want the installed one kept aside", name, got)
		}
		if got := run.content(t, name+".new"); got != "missing" {
			t.Errorf("%s.new left behind", name)
		}
	}
	daemon := filepath.Join(run.install, windowsDaemonName)
	if len(run.stops) != 2 || run.stops[0] != daemon || run.stops[1] != daemon+".old" {
		t.Errorf("stops = %q, want this install's agent, then one running from the .old copy", run.stops)
	}
	if run.starts != 1 {
		t.Errorf("starts = %d, want 1", run.starts)
	}
	if !strings.Contains(out.String(), "Background agent runs 9.9.9 (was 1.0.0)") {
		t.Errorf("output does not name the versions:\n%s", out.String())
	}
}

func TestUpdateFailsWhenTheOldAgentStillAnswers(t *testing.T) {
	run := newUpdateRun(t)
	run.startedVersion = "1.0.0" // what answers is the old agent
	err := Update(context.Background(), UpdateOptions{Version: "9.9.9"})
	if err == nil || !strings.Contains(err.Error(), `not the new "9.9.9"`) {
		t.Fatalf("Update = %v, want it to name the old agent that answers", err)
	}
}

func TestUpdatePutsTheOldProgramsBackWhenASwapFails(t *testing.T) {
	run := newUpdateRun(t)
	run.renameFails = filepath.Join(run.install, "kontext.exe.old") // the second program
	var out bytes.Buffer
	err := Update(context.Background(), UpdateOptions{Version: "9.9.9", Stdout: &out})
	if err == nil || !strings.Contains(err.Error(), "move the installed kontext.exe aside") {
		t.Fatalf("Update = %v, want the failed swap named", err)
	}
	for _, name := range updatePrograms {
		if got := run.content(t, name); got != "old "+name {
			t.Errorf("%s = %q after the failed update, want the installed one back", name, got)
		}
		for _, suffix := range []string{".old", ".new"} {
			if got := run.content(t, name+suffix); got != "missing" {
				t.Errorf("%s%s left behind: %q", name, suffix, got)
			}
		}
	}
	if run.starts != 1 || !strings.Contains(out.String(), "background agent runs again") {
		t.Errorf("starts = %d, output:\n%s\nwant the old agent started again", run.starts, out.String())
	}
}

func TestUpdateRefusesAndChangesNothing(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		arrange    func(t *testing.T, run *updateRun)
	}{
		{"not on Windows", "with the package manager", func(t *testing.T, run *updateRun) { overrideVar(t, &goos, "darwin") }},
		{"machine-wide install", "managed by your organization", func(t *testing.T, run *updateRun) {
			if err := os.MkdirAll(filepath.Dir(systemConfigPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(systemConfigPath, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"no install", "no install of yours", func(t *testing.T, run *updateRun) {
			overrideVar(t, &readWindowsAutostart, func() (string, error) { return "", nil })
		}},
		{"run from the install", "this is the installed program", func(t *testing.T, run *updateRun) {
			overrideVar(t, &executablePath, func() (string, error) { return filepath.Join(run.install, "kontext.exe"), nil })
		}},
		{"release incomplete", "missing beside this program", func(t *testing.T, run *updateRun) {
			if err := os.Remove(filepath.Join(run.release, windowsDaemonName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"stop fails", "stop the background agent", func(t *testing.T, run *updateRun) {
			overrideVar(t, &stopWindowsDaemon, func(string) (bool, error) { return false, errors.New("access is denied") })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := newUpdateRun(t)
			tc.arrange(t, run)
			err := Update(context.Background(), UpdateOptions{Version: "9.9.9"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Update = %v, want %q", err, tc.want)
			}
			entries, _ := os.ReadDir(run.install)
			if len(entries) != len(updatePrograms) {
				t.Errorf("install folder holds %d files after a refusal, want only the programs", len(entries))
			}
			for _, name := range updatePrograms {
				if got := run.content(t, name); got != "old "+name {
					t.Errorf("%s = %q, want it untouched", name, got)
				}
			}
			if run.starts != 0 {
				t.Errorf("an agent was started by a refused update")
			}
		})
	}
}

func TestUpdateRemovesTheCopiesOfAnEarlierUpdate(t *testing.T) {
	run := newUpdateRun(t)
	for _, name := range updatePrograms {
		if err := os.WriteFile(filepath.Join(run.install, name+".old"), []byte("older"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := Update(context.Background(), UpdateOptions{Version: "9.9.9"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range updatePrograms {
		if got := run.content(t, name+".old"); got != "old "+name {
			t.Errorf("%s.old = %q, want the program this update replaced", name, got)
		}
	}
}
