//go:build windows

package managedobserve

import "github.com/kontext-security/kontext/internal/processalive"

// daemonAlive reports whether pid names a running process. Windows has no
// signal 0; processalive opens the process and asks.
func daemonAlive(pid int) bool { return processalive.Alive(pid) }
