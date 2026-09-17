package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
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
	return probeFullDiskAccess(filepath.Join(home, "Library", "Mail"))
}

func probeFullDiskAccess(path string) *bool {
	file, err := os.Open(path)
	if err != nil {
		return fullDiskAccessResult(err)
	}
	defer file.Close()
	_, err = file.Readdirnames(1)
	return fullDiskAccessResult(err)
}

func fullDiskAccessResult(err error) *bool {
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if err != nil && !errors.Is(err, syscall.EPERM) {
		return nil
	}
	accessible := err == nil
	return &accessible
}
