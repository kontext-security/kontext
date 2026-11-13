package setup

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/kontext-security/kontext/internal/managedobserve"
)

// startSleeperAt runs a copy of this test binary at program, sleeping, as a
// stand-in for a background agent started from that file.
func startSleeperAt(t *testing.T, program string) *exec.Cmd {
	t.Helper()
	if _, err := os.Stat(program); err != nil {
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(self)
		if err != nil {
			t.Fatal(err)
		}
		target, err := os.OpenFile(program, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(target, source); err != nil {
			t.Fatal(err)
		}
		source.Close()
		if err := target.Close(); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(program, "-test.run=^TestHelperSleeps$")
	cmd.Env = append(os.Environ(), "KONTEXT_TEST_SLEEP=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	return cmd
}

// A running program renamed aside reports its new name, so the stop that
// follows an update's renames has to know the daemon by that name too, and
// still only by its own file.
func TestStopProcessEndsADaemonRenamedAside(t *testing.T) {
	dir := t.TempDir()
	daemon := filepath.Join(dir, windowsDaemonName)
	agent := startSleeperAt(t, daemon)
	time.Sleep(300 * time.Millisecond)
	if err := os.Rename(daemon, daemon+".old"); err != nil {
		t.Fatalf("rename the running program aside: %v", err)
	}
	if err := os.WriteFile(daemon, []byte("the new program"), 0o755); err != nil {
		t.Fatal(err)
	}
	if stopped, err := stopProcess(agent.Process.Pid, daemon); err != nil || stopped {
		t.Fatalf("stopProcess(pid, the new file) = %v, %v; want the renamed daemon left alone", stopped, err)
	}
	if exited(agent, 300*time.Millisecond) {
		t.Fatal("the renamed daemon ended for a stop that named the new file")
	}
	stopped, err := stopProcess(agent.Process.Pid, daemon+".old")
	if err != nil || !stopped {
		t.Fatalf("stopProcess(pid, the renamed file) = %v, %v; want it ended", stopped, err)
	}
	if !exited(agent, 5*time.Second) {
		t.Fatal("the renamed daemon is still running")
	}
}

// The race the update guards against, with real processes and real renames:
// right after the update stops the agent, a hook starts the old program again;
// the update renames it aside while it runs, and has to end it before the new
// agent starts.
func TestUpdateEndsAnOldAgentAHookStartedMeanwhile(t *testing.T) {
	run := newUpdateRun(t)
	daemon := filepath.Join(run.install, windowsDaemonName)
	if err := os.Remove(daemon); err != nil {
		t.Fatal(err)
	}
	old := startSleeperAt(t, daemon)
	run.status = &managedobserve.DaemonStatus{Version: "1.0.0", PID: old.Process.Pid}
	var respawned *exec.Cmd
	var secondStop error
	overrideVar(t, &stopWindowsDaemon, func(program string) (bool, error) {
		if respawned == nil {
			stopped, err := stopProcess(old.Process.Pid, program)
			if err != nil || !stopped {
				t.Fatalf("stop the old agent: %v, %v", stopped, err)
			}
			respawned = startSleeperAt(t, daemon) // the hook's start
			time.Sleep(300 * time.Millisecond)
			return true, nil
		}
		stopped, err := stopProcess(respawned.Process.Pid, program)
		if err == nil && !stopped {
			secondStop = os.ErrProcessDone
		}
		return stopped, err
	})
	if err := Update(context.Background(), UpdateOptions{Version: "9.9.9"}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if secondStop != nil {
		t.Fatal("the agent the hook started was not ended")
	}
	if !exited(respawned, 5*time.Second) {
		t.Fatal("the agent the hook started is still running from the .old copy")
	}
	if got := run.content(t, windowsDaemonName); got != "new "+windowsDaemonName {
		t.Errorf("%s = %q, want the release's", windowsDaemonName, got)
	}
}

// A process that has ended but is still held open by someone is not there to
// stop, and asking for its program is no error.
func TestStopProcessTakesAnEndedProcessAsGone(t *testing.T) {
	dir := t.TempDir()
	daemon := filepath.Join(dir, windowsDaemonName)
	agent := startSleeperAt(t, daemon)
	time.Sleep(300 * time.Millisecond)
	if err := agent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	// exec keeps its handle until Wait, so the process object stays.
	time.Sleep(300 * time.Millisecond)
	stopped, err := stopProcess(agent.Process.Pid, daemon)
	if err != nil || stopped {
		t.Fatalf("stopProcess(an ended process) = %v, %v; want false, nil", stopped, err)
	}
}
