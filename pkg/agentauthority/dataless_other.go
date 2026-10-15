//go:build !unix && !windows

package agentauthority

import "os"

// isDataless has no placeholder check on targets that are neither unix nor Windows; readGuarded
// refuses every read there anyway (limits_other.go).
func isDataless(os.FileInfo) bool { return false }
