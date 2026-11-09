package installation

import (
	"path/filepath"

	"github.com/kontext-security/kontext/internal/platform"
)

// SystemPath is where an organization-managed daemon keeps its identity. On
// Windows that's the user's own state folder: each user's daemon is its own
// installation, created by that user, so no user can take another's. It is ""
// if the folder can't be worked out.
func SystemPath() string {
	dir, err := platform.UserStateDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "installation.json")
}
