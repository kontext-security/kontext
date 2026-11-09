package managedconfig

import (
	"errors"
	"fmt"

	"github.com/kontext-security/kontext/internal/fsperm"
)

// readAdminOnlyRegistry reads a string value under HKLM only if nobody but an
// administrator could have written it. The key's access list decides: a value has
// none of its own.
func readAdminOnlyRegistry(key, name string) (string, error) {
	value, err := fsperm.ReadAdminOnlyRegistryString(key, name)
	var refused *fsperm.NotAdminOnlyError
	if errors.As(err, &refused) {
		return "", fmt.Errorf("%w: HKLM\\%s: %s; an administrator has to make the key owned and writable by administrators only", ErrUntrustedSystemConfig, key, refused.Reason)
	}
	return value, err
}
