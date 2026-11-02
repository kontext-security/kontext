package managedconfig

import (
	"errors"
	"fmt"

	"github.com/kontext-security/kontext/internal/fsperm"
)

func systemFileNotAdmins(path string) (fmt.Stringer, error) {
	found, err := fsperm.FindNotAdminFile(path)
	if found == nil {
		return nil, err // A nil pointer in the interface would read as found.
	}
	return found, err
}

func readAdminOnly(path string) ([]byte, error) {
	data, err := fsperm.ReadAdminOnly(path)
	var refused *fsperm.NotAdminOnlyError
	if errors.As(err, &refused) {
		return nil, fmt.Errorf("%w: %s: %s; an administrator has to remove the file, or make it and its folder owned and writable by administrators only", ErrUntrustedSystemConfig, path, refused)
	}
	return data, err
}
