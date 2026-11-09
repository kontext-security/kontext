//go:build !windows

package installation

// SystemPath is where an organization-managed daemon keeps its identity: the
// folder the macOS package owns.
func SystemPath() string {
	return DefaultPath
}
