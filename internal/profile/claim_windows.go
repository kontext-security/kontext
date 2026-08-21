//go:build windows

package profile

// pidAlive always reports false on Windows: profiles are macOS-only, this
// stub only keeps the package compiling there — a claim never pins a
// directory on a platform where nothing creates one.
func pidAlive(int) bool {
	return false
}
