//go:build !windows

package managedconfig

import "os"

// readAdminOnly is a plain read on this OS.
func readAdminOnly(path string) ([]byte, error) {
	return os.ReadFile(path)
}
