//go:build !unix

package mcpconfig

import "testing"

func testMkfifo(t *testing.T, _ string) {
	t.Helper()
	t.Skip("no FIFO special files on this platform")
}
