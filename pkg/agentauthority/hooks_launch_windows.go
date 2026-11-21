//go:build windows

package agentauthority

import "os"

// launchable: Windows has no execute bits; a file that exists can be run.
func launchable(string, os.FileInfo) bool { return true }
