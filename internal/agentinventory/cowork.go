package agentinventory

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/kontext-security/kontext/pkg/agentauthority"
)

const (
	coworkHostSessions = "Library/Application Support/Claude/local-agent-mode-sessions"
	coworkVMBundle     = "Library/Application Support/Claude/vm_bundles/claudevm.bundle"
	coworkVMLog        = "Library/Logs/Claude/cowork_vm_swift.log"
	coworkVMSessions   = "Library/Application Support/Claude/claude-code-sessions"
)

func coworkSandbox(ctx context.Context, home string, now time.Time, hasSessions func(time.Time) (bool, error)) *bool {
	if hasSessions == nil {
		return nil
	}
	since := now.Add(-30 * 24 * time.Hour)
	observed, err := hasSessions(since)
	if err != nil {
		return nil
	}
	if observed {
		sandboxed := false
		return &sandboxed
	}
	data, err := agentauthority.CoworkVMLogTail(ctx, home)
	if err != nil && !os.IsNotExist(err) {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "vm_boot completed") || !strings.HasPrefix(line, "[VM] ") || len(line) < 24 {
			continue
		}
		// The native logger writes local wall-clock time without a zone.
		boot, err := time.ParseInLocation("2006-01-02 15:04:05", line[5:24], now.Location())
		if err != nil || boot.Before(since) || boot.After(now) {
			continue
		}
		sandboxed := true
		return &sandboxed
	}
	return nil
}
