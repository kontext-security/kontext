package browserevents

import "os"

// openNoBlock is zero on Windows, which has no FIFOs in the file system.
const openNoBlock = 0

// trustedFile is the DACL check on Windows: mode bits say nothing of it, so
// only a private file is trusted.
func trustedFile(private bool, _ os.FileInfo) bool {
	return private
}
