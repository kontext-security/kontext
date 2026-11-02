//go:build !windows

package platform_test

import "testing"

func wantCodexDir(*testing.T) string {
	return "/etc/codex"
}
