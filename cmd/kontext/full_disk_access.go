package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// Run in the hook process: macOS grants follow the invoking agent's app,
// not the separately launched daemon. Missing Mail is not proof of access.
func hookFullDiskAccess() *bool {
	if runtime.GOOS != "darwin" {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	_, err = os.Stat(filepath.Join(home, "Library", "Mail"))
	return fullDiskAccessResult(err)
}

func fullDiskAccessResult(err error) *bool {
	if err != nil && !errors.Is(err, fs.ErrPermission) {
		return nil
	}
	accessible := err == nil
	return &accessible
}
