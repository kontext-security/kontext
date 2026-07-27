//go:build windows

package managedconfig

// WithWriteLock is a no-op on Windows: the managed-observe daemon and
// `kontext setup` are not shipped for Windows, this stub only keeps the
// package compiling there.
func WithWriteLock(_ string, fn func() error) error {
	return fn()
}
