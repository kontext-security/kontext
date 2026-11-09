//go:build !windows

package main

// redirectDaemonLog keeps the error output as it is: launchd and systemd capture
// it on these systems.
func redirectDaemonLog() func() {
	return func() {}
}
