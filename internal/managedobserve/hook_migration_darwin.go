package managedobserve

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func hookMigrationCanPrompt() bool {
	info, err := os.Stat("/dev/console")
	if err != nil || os.Geteuid() == 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

func approveClaudeHookMigration(ctx context.Context, executable, binary, digest string) error {
	script := claudeHookApprovalScript(executable, binary, digest)
	out, err := exec.CommandContext(ctx, "/usr/bin/osascript", "-e", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Claude hook update was not approved or failed: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
