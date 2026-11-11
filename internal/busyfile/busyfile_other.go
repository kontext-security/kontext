//go:build !windows

// Package busyfile reads, replaces and removes small state files that
// another process may have open at that moment: the daemon replaces them
// while doctor reads them. Windows refuses a rename or a remove while a
// reader has the file open, and an open while the file is being replaced.
// The functions here try again for a moment there; on this OS they are the
// plain os calls.
package busyfile

import "os"

// Rename renames from over to, as os.Rename does.
func Rename(from, to string) error { return os.Rename(from, to) }

// ReadFile reads path, as os.ReadFile does.
func ReadFile(path string) ([]byte, error) { return os.ReadFile(path) }

// Remove removes path, as os.Remove does.
func Remove(path string) error { return os.Remove(path) }
