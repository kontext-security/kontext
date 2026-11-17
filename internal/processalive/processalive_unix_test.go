//go:build !windows

package processalive

import (
	"os"
	"testing"
)

// pid 1 (init or launchd) runs as root: a process of another user is there.
func TestAliveCountsAnotherUsersProcess(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root, every process is this user's")
	}
	if !Alive(1) {
		t.Fatal("pid 1 does not count as alive")
	}
}
