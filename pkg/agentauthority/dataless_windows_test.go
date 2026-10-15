//go:build windows

package agentauthority

import (
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

type attributeInfo struct {
	os.FileInfo
	data syscall.Win32FileAttributeData
}

func (i attributeInfo) Sys() any { return &i.data }

func TestDatalessRecallAttributes(t *testing.T) {
	info, err := os.Lstat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		attrs uint32
		want  bool
	}{
		{"plain directory", windows.FILE_ATTRIBUTE_DIRECTORY, false},
		{"plain file", windows.FILE_ATTRIBUTE_ARCHIVE, false},
		// Placeholder directories keep the directory bit, so the check must not skip them.
		{"placeholder directory", windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_RECALL_ON_OPEN, true},
		{"placeholder file", windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, true},
		{"offline file", windows.FILE_ATTRIBUTE_ARCHIVE | windows.FILE_ATTRIBUTE_OFFLINE, true},
	} {
		if got := isDataless(attributeInfo{info, syscall.Win32FileAttributeData{FileAttributes: tc.attrs}}); got != tc.want {
			t.Errorf("%s: isDataless = %v, want %v", tc.name, got, tc.want)
		}
	}
}
