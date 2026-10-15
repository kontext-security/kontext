//go:build unix

package agentinventory

import (
	"syscall"
	"testing"
)

func testMkfifo(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
}
