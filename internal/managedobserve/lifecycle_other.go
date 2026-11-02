//go:build !windows

package managedobserve

// winsockConnectionLost is Windows only; elsewhere the syscall errnos in
// connectionLost are the ones the OS reports.
func winsockConnectionLost(error) bool { return false }
