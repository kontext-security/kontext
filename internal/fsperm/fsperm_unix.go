//go:build unix

package fsperm

import "os"

// Requirement names what PrivateFile checks, for error messages.
const Requirement = "0600 permissions"

// RestrictFile narrows an open file to its owner: mode 0600.
func RestrictFile(file *os.File) error {
	return file.Chmod(0o600)
}

// PrivateFile reports whether the file at path is private to its owner: mode 0600.
func PrivateFile(_ string, info os.FileInfo) (bool, error) {
	return info.Mode().Perm() == 0o600, nil
}
