//go:build !windows

package managedconfig

import (
	"fmt"
	"os"
)

// systemFileNotAdmins rules nothing out on this OS.
func systemFileNotAdmins(string) (fmt.Stringer, error) {
	return nil, nil
}

// readAdminOnly is a plain read on this OS.
func readAdminOnly(path string) ([]byte, error) {
	return os.ReadFile(path)
}
