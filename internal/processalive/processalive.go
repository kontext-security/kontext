// Package processalive answers one question the same way everywhere: is a
// process with this pid running? Doctor asks it about the background agent's
// pid, and the profile claim about the pid that holds a claim.
package processalive

// Alive reports whether pid names a running process. A process that exists
// under another user counts as running: it is there, only not ours to touch.
func Alive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return alive(pid)
}
