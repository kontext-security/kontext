//go:build darwin

package managedobserve

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

// healLaunchAgentPriority fixes an installed plist from an older setup and
// reloads the agent so the running daemon gets the new class. Only the
// self-serve plist in the user's LaunchAgents is touched; an MDM-managed
// daemon is not ours to rewrite. The reload runs detached because bootout
// ends this process.
func healLaunchAgentPriority(label string, log diagnostic.Logger) {
	// launchd names the service it started; a daemon run by hand or by a test
	// must not rewrite and reload the user's agent.
	if os.Getenv("XPC_SERVICE_NAME") != label {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
	raw, err := os.ReadFile(plistPath)
	if err != nil {
		return
	}
	next, changed := healPlist(string(raw))
	if !changed {
		return
	}
	if err := os.WriteFile(plistPath, []byte(next), 0o644); err != nil {
		logAlways(log, "launch agent priority: rewrite %s: %v\n", plistPath, err)
		return
	}
	// bootout tears the job down asynchronously; a bootstrap that lands
	// during the teardown fails with "Input/output error" and would leave
	// the job unloaded, beyond the reach of KeepAlive and the hook's
	// kickstart. So bootstrap retries for a while and reports the outcome on
	// the daemon's own stdout/stderr, which launchd already points at the log.
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	script := fmt.Sprintf(`sleep 2
launchctl bootout %[1]s/%[2]s
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
	if launchctl bootstrap %[1]s %[3]q; then
		echo "launch agent: reloaded after rewrite (bootstrap attempt $attempt)"
		exit 0
	fi
	sleep 1
done
echo "launch agent: bootstrap failed after rewrite; the daemon is unloaded, run kontext setup" >&2
exit 1`, domain, label, plistPath)
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		logAlways(log, "launch agent priority: reload: %v\n", err)
		return
	}
	logAlways(log, "launch agent: plist used the Background class or a 30 s relaunch throttle; rewrote it and reloading\n")
}
