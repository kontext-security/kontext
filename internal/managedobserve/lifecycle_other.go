//go:build !windows

package managedobserve

import "context"

// winsockConnectionLost is Windows only; elsewhere the syscall errnos in
// connectionLost are the ones the OS reports.
func winsockConnectionLost(error) bool { return false }

// kickstartDaemon is what a hook does when nothing listens on the daemon's
// socket: ask launchd, which does nothing off macOS.
func kickstartDaemon(ctx context.Context, label string) error {
	return KickstartLaunchd(ctx, label)
}
