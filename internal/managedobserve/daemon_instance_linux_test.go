//go:build linux

package managedobserve

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/kontext-security/kontext/internal/diagnostic"
	"github.com/kontext-security/kontext/internal/hermetic"
)

// A live daemon whose accept queue is full fails a connect. That's a busy daemon,
// not a leftover file, and replacing it would take its socket.
func TestSocketAnswersWhenItsQueueIsFull(t *testing.T) {
	path := filepath.Join(hermetic.SocketDir(t), "s.sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: path}); err != nil {
		t.Fatal(err)
	}
	// Go's net.Listen asks for the system's largest backlog; this never accepts.
	if err := unix.Listen(fd, 0); err != nil {
		t.Fatal(err)
	}

	full := false
	for range 16 {
		conn, err := net.DialTimeout("unix", path, 100*time.Millisecond)
		if err != nil {
			t.Logf("queue full: %v", err)
			full = true
			break
		}
		t.Cleanup(func() { conn.Close() })
	}
	if !full {
		t.Fatal("the queue never filled")
	}
	if !socketAnswers(path, diagnostic.Logger{}) {
		t.Error("a listener with a full queue read as nothing there")
	}
}
