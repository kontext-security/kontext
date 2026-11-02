package managedconfig

import (
	"errors"
	"fmt"

	"github.com/kontext-security/kontext/internal/fsperm"
)

func readAdminOnly(path string) ([]byte, error) {
	data, err := fsperm.ReadAdminOnly(path)
	var refused *fsperm.NotAdminOnlyError
	if errors.As(err, &refused) {
		return nil, fmt.Errorf("%w: %s: %s; an administrator has to remove the file, or make it and its folder owned and writable by administrators only", ErrUntrustedSystemConfig, path, refused)
	}
	return data, err
}
