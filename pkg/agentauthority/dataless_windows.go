//go:build windows

package agentauthority

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// Cloud placeholders (OneDrive Files On-Demand and other cloud filter drivers) carry these
// attributes, directories included; reading through them downloads the content.
const placeholderAttributes = windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | windows.FILE_ATTRIBUTE_RECALL_ON_OPEN | windows.FILE_ATTRIBUTE_OFFLINE

func isDataless(info os.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&placeholderAttributes != 0
}
