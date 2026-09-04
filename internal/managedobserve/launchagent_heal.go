package managedobserve

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kontext-security/kontext/internal/diagnostic"
)

const backgroundProcessType = "<key>ProcessType</key>\n\t<string>Background</string>"
const standardProcessType = "<key>ProcessType</key>\n\t<string>Standard</string>"

// raiseProcessType rewrites a LaunchAgent plist that runs the daemon in
// launchd's Background class to Standard. Background is macOS's throttled
// QoS: the daemon starves whenever the user does anything, and the hook,
// a foreground process with a 250 ms budget, reads that as a dead daemon and
// fails closed in enforce. Returns false when nothing needed changing.
func raiseProcessType(plist string) (string, bool) {
	if !strings.Contains(plist, backgroundProcessType) {
		return plist, false
	}
	return strings.Replace(plist, backgroundProcessType, standardProcessType, 1), true
}

// healLaunchAgentPriority fixes an installed plist from an older setup and
// reloads the agent so the running daemon gets the new class. Only the
// self-serve plist in the user's LaunchAgents is touched; an MDM-managed
// daemon is not ours to rewrite. The reload runs detached because bootout
// ends this process.
func healLaunchAgentPriority(label string, log diagnostic.Logger) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	plistPath := filepath.Join(home, "Library", "LaunchAgents", label+".plist")
	raw, err := os.ReadFile(plistPath)
	if err != nil {
		return
	}
	next, changed := raiseProcessType(string(raw))
	if !changed {
		return
	}
	if err := os.WriteFile(plistPath, []byte(next), 0o644); err != nil {
		logAlways(log, "launch agent priority: rewrite %s: %v\n", plistPath, err)
		return
	}
	domain := fmt.Sprintf("gui/%d", os.Getuid())
	script := fmt.Sprintf("sleep 2; launchctl bootout %s/%s; launchctl bootstrap %s %q", domain, label, domain, plistPath)
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		logAlways(log, "launch agent priority: reload: %v\n", err)
		return
	}
	logAlways(log, "launch agent priority: plist ran the daemon in the Background class; rewrote it to Standard and reloading\n")
}
