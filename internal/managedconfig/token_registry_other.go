//go:build !windows

package managedconfig

import "errors"

// readAdminOnlyRegistry has no registry to read on this OS.
func readAdminOnlyRegistry(string, string) (string, error) {
	return "", errors.New("registry install token refs are only supported on Windows")
}
