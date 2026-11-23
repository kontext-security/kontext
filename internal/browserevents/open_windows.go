package browserevents

import "os"

// openNoBlock is zero on Windows, which has no FIFOs in the file system.
const openNoBlock = 0

// onlyOwnerMode is false on Windows: mode bits say nothing of the DACL, so
// only a private file is trusted.
func onlyOwnerMode(os.FileInfo) bool {
	return false
}
