//go:build !darwin

package managedobserve

import (
	"context"
	"errors"
)

func hookMigrationCanPrompt() bool { return false }

func approveClaudeHookMigration(context.Context, string, string, string) error {
	return errors.New("Claude hook migration requires macOS")
}
