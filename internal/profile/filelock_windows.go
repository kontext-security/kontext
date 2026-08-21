//go:build windows

package profile

// withPointerLock is a no-op on Windows: profiles are macOS-only, this stub
// only keeps the package compiling there.
func withPointerLock(_ string, fn func() error) error {
	return fn()
}
