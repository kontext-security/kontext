//go:build !windows

package fsperm

import "os"

// SyncDir flushes a directory, so a rename or link inside it survives a crash.
func SyncDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
